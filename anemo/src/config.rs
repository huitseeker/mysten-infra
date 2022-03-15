use std::marker::PhantomData;

use std::{future::Future, net::IpAddr, sync::Arc, time::Duration};

use quinn::IdleTimeout;
use rccheck::rustls;
use rccheck::Certifiable;
use rccheck::Psk;
use rustls::{Certificate, ClientConfig, PrivateKey};

use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};

/// Default for [`Config::idle_timeout`] (1 minute).
///
/// This is based on average time in which routers would close the UDP mapping to the peer if they
/// see no conversation between them.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// This type provides serialized bytes for a private key.
///
/// The private key must be DER-encoded ASN.1 in either
/// PKCS#8 or PKCS#1 format.
// TODO: move this to rccheck?
pub trait ToPKCS8 {
    fn to_pkcs8_bytes(&self) -> Vec<u8>;
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CertAndKey {
    #[serde_as(as = "Bytes")]
    cert: Vec<u8>,
    #[serde_as(as = "Bytes")]
    private_key: Vec<u8>,
}

impl CertAndKey {
    fn cert(&self) -> rustls::Certificate {
        Certificate(self.cert.clone())
    }
    fn key(&self) -> rustls::PrivateKey {
        PrivateKey(self.private_key.clone())
    }
}

/// QuicP2p configurations
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MachineConfig<Scheme> {
    marker: PhantomData<Scheme>,

    key_material: CertAndKey,

    server_name: String,

    /// External port number assigned to the socket address of the program.
    external_port: u16,

    /// External IP address of the computer on the WAN.
    pub external_ip: Option<IpAddr>,

    /// How long to wait to hear from a peer before timing out a connection.
    ///
    /// In the absence of any keep-alive messages, connections will be closed if they remain idle
    /// for at least this duration.
    ///
    /// If unspecified, this will default to [`DEFAULT_IDLE_TIMEOUT`].
    #[serde(default)]
    pub idle_timeout: Option<Duration>,

    /// Interval at which to send keep-alives to maintain otherwise idle connections.
    ///
    /// Keep-alives prevent otherwise idle connections from timing out.
    ///
    /// If unspecified, this will default to `None`, disabling keep-alives.
    #[serde(default)]
    pub keep_alive_interval: Option<Duration>,

    /// Retry configurations for establishing connections and sending messages.
    /// Determines the retry behaviour of requests, by setting the back off strategy used.
    #[serde(default)]
    pub retry_config: RetryConfig,
}

impl<Scheme> MachineConfig<Scheme>
where
    Scheme: Certifiable,
    Scheme::KeyPair: ToPKCS8,
{
    fn generate_cert(kp: Scheme::KeyPair, name: &str) -> Result<CertAndKey> {
        let private_key = Scheme::KeyPair::to_pkcs8_bytes(&kp);
        let cert = Scheme::keypair_to_certificate(vec![name.to_string()], kp)?
            .as_ref()
            .to_vec();

        Ok(CertAndKey { cert, private_key })
    }

    pub fn new(
        kp: Scheme::KeyPair,
        server_name: &str,
        external_port: u16,
        external_ip: Option<IpAddr>,
    ) -> Result<Self> {
        let key_material = Self::generate_cert(kp, server_name)?;
        let server_name = server_name.to_owned();
        Ok(MachineConfig {
            marker: PhantomData,
            key_material,
            server_name,
            external_port,
            external_ip,
            idle_timeout: None,
            keep_alive_interval: None,
            retry_config: RetryConfig::default(),
        })
    }
}

/// Retry configurations for establishing connections and sending messages.
/// Determines the retry behaviour of requests, by setting the back off strategy used.
#[derive(Clone, Debug, Copy, Serialize, Deserialize)]
pub struct RetryConfig {
    /// The initial retry interval.
    ///
    /// This is the first delay before a retry, for establishing connections and sending messages.
    /// The subsequent delay will be decided by the `retry_delay_multiplier`.
    pub initial_retry_interval: Duration,
    /// The maximum value of the back off period. Once the retry interval reaches this
    /// value it stops increasing.
    ///
    /// This is the longest duration we will have,
    /// for establishing connections and sending messages.
    /// Retrying continues even after the duration times have reached this duration.
    /// The number of retries before that happens, will be decided by the `retry_delay_multiplier`.
    /// The number of retries after that, will be decided by the `retrying_max_elapsed_time`.
    pub max_retry_interval: Duration,
    /// The value to multiply the current interval with for each retry attempt.
    pub retry_delay_multiplier: f64,
    /// The randomization factor to use for creating a range around the retry interval.
    ///
    /// A randomization factor of 0.5 results in a random period ranging between 50% below and 50%
    /// above the retry interval.
    pub retry_delay_rand_factor: f64,
    /// The maximum elapsed time after instantiating
    ///
    /// Retrying continues until this time has elapsed.
    /// The number of retries before that happens, will be decided by the other retry config options.
    pub retrying_max_elapsed_time: Duration,
}

impl RetryConfig {
    // Together with the default max and multiplier,
    // default gives 5-6 retries in ~30 s total retry time.

    /// Default for [`RetryConfig::max_retry_interval`] (500 ms).
    pub const DEFAULT_INITIAL_RETRY_INTERVAL: Duration = Duration::from_millis(500);

    /// Default for [`RetryConfig::max_retry_interval`] (15 s).
    pub const DEFAULT_MAX_RETRY_INTERVAL: Duration = Duration::from_secs(15);

    /// Default for [`RetryConfig::retry_delay_multiplier`] (x1.5).
    pub const DEFAULT_RETRY_INTERVAL_MULTIPLIER: f64 = 1.5;

    /// Default for [`RetryConfig::retry_delay_rand_factor`] (0.3).
    pub const DEFAULT_RETRY_DELAY_RAND_FACTOR: f64 = 0.3;

    /// Default for [`RetryConfig::retrying_max_elapsed_time`] (30 s).
    pub const DEFAULT_RETRYING_MAX_ELAPSED_TIME: Duration = Duration::from_secs(30);

    // Perform `op` and retry on errors as specified by this configuration.
    //
    // Note that `backoff::Error<E>` implements `From<E>` for any `E` by creating a
    // `backoff::Error::Transient`, meaning that errors will be retried unless explicitly returning
    // `backoff::Error::Permanent`.
    pub(crate) fn retry<R, E, Fn, Fut>(&self, op: Fn) -> impl Future<Output = Result<R, E>>
    where
        Fn: FnMut() -> Fut,
        Fut: Future<Output = Result<R, backoff::Error<E>>>,
    {
        let backoff = backoff::ExponentialBackoff {
            initial_interval: self.initial_retry_interval,
            randomization_factor: self.retry_delay_rand_factor,
            multiplier: self.retry_delay_multiplier,
            max_interval: self.max_retry_interval,
            max_elapsed_time: Some(self.retrying_max_elapsed_time),
            ..Default::default()
        };
        backoff::future::retry(backoff, op)
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            initial_retry_interval: RetryConfig::DEFAULT_INITIAL_RETRY_INTERVAL,
            max_retry_interval: RetryConfig::DEFAULT_MAX_RETRY_INTERVAL,
            retry_delay_multiplier: RetryConfig::DEFAULT_RETRY_INTERVAL_MULTIPLIER,
            retry_delay_rand_factor: RetryConfig::DEFAULT_RETRY_DELAY_RAND_FACTOR,
            retrying_max_elapsed_time: RetryConfig::DEFAULT_RETRYING_MAX_ELAPSED_TIME,
        }
    }
}

// Convenience alias – not for export.
type Result<T, E = ConfigError> = std::result::Result<T, E>;

impl From<anyhow::Error> for ConfigError {
    fn from(error: anyhow::Error) -> Self {
        Self::CertificateGeneration(CertificateGenerationError(error.into()))
    }
}

/// An error that occured when generating the TLS certificate.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct CertificateGenerationError(
    // Though there are multiple different errors that could occur by the code, since we are
    // generating a certificate, they should only really occur due to buggy implementations. As
    // such, we don't attempt to expose more detail than 'something went wrong', which will
    // hopefully be enough for someone to file a bug report...
    Box<dyn std::error::Error + Send + Sync>,
);

/// Configuration errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("An error occurred when generating the TLS certificate")]
    CertificateGeneration(#[from] CertificateGenerationError),

    #[error("An error occurred parsing idle timeout duration")]
    InvalidIdleTimeout(#[from] quinn_proto::VarIntBoundsExceeded),

    #[error("An error occurred within rustls")]
    Rustls(#[from] rustls::Error),

    #[error("An error occurred generating client config certificates")]
    Webpki,
}

impl<Scheme> MachineConfig<Scheme> {
    // convert our duration to quinn's IdleTimeout
    fn quinn_timeout(opt_timeout: Option<Duration>) -> Result<IdleTimeout> {
        let default_idle_timeout: IdleTimeout = IdleTimeout::try_from(DEFAULT_IDLE_TIMEOUT)?; // 60s

        opt_timeout
            .map(IdleTimeout::try_from)
            // TODO: IdleTImeout caps out at 2^62, we should fallback to some IDLE_TIMEOUT_MAX instead
            .unwrap_or(Ok(default_idle_timeout))
            .map_err(ConfigError::from)
    }

    // set up a TransportConfig from defaults
    fn default_transport_config(
        idle_timeout: IdleTimeout,
        keep_alive_interval: Option<Duration>,
    ) -> Arc<quinn::TransportConfig> {
        let mut config = quinn::TransportConfig::default();

        let _ = config.max_idle_timeout(Some(idle_timeout));
        let _ = config.keep_alive_interval(keep_alive_interval);

        Arc::new(config)
    }

    // Generates a server config from the machine config. This checks the client certificate is
    // self-signed by the key which SubjectPublicKeyInfo (as bytes) are passed as an argument.
    pub fn server_config_for(
        &self,
        // DER-encoded public key bytes
        target_public_key_bytes: &[u8],
    ) -> Result<quinn::ServerConfig> {
        let idle_timeout = Self::quinn_timeout(self.idle_timeout)?;
        let keep_alive_interval = self.keep_alive_interval;

        let transport = Self::default_transport_config(idle_timeout, keep_alive_interval);

        let pubkey_verifier = Psk::from_der(target_public_key_bytes)?;

        // setup certificates
        let cert: Certificate = self.key_material.cert();
        let key: PrivateKey = self.key_material.key();
        let server_crypto = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(Arc::new(pubkey_verifier))
            .with_single_cert(vec![cert], key)?;

        let mut server = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
        server.transport = transport;
        Ok(server)
    }

    // Generates a client config from the machine config. This checks the server certificate is
    // self-signed by the key which SubjectPublicKeyInfo (as bytes) are passed as an argument.
    pub fn client_config_for(
        &self,
        // DER-encoded public key bytes
        target_public_key_bytes: &[u8],
    ) -> Result<quinn::ClientConfig> {
        let idle_timeout = Self::quinn_timeout(self.idle_timeout)?;
        let keep_alive_interval = self.keep_alive_interval;

        let transport = Self::default_transport_config(idle_timeout, keep_alive_interval);

        // setup certificates
        let mut roots = rustls::RootCertStore::empty();

        let cert: Certificate = self.key_material.cert();
        let key: PrivateKey = self.key_material.key();
        roots.add(&cert).map_err(|_e| ConfigError::Webpki)?;

        let pubkey_verifier = Psk::from_der(target_public_key_bytes)?;

        let client_crypto = ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(pubkey_verifier))
            .with_single_cert(vec![cert], key)?;

        let mut client = quinn::ClientConfig::new(Arc::new(client_crypto));
        client.transport = transport;

        Ok(client)
    }
}
