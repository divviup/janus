//! Common functionality for PPM aggregators
use crate::{
    hpke::HpkeRecipient,
    message::{HpkeConfigId, Nonce, Report, Role},
    time::Clock,
};
use bytes::Bytes;
use chrono::Duration;
use http::{header::CACHE_CONTROL, StatusCode};
use prio::codec::{Decode, Encode};
use std::{
    collections::HashMap,
    convert::Infallible,
    future::Future,
    net::SocketAddr,
    ops::Sub,
    sync::{Arc, Mutex},
};
use tracing::warn;
use warp::{filters::BoxedFilter, reply, trace, Filter, Rejection, Reply};

/// Errors returned by functions and methods in this module
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An invalid configuration was passed.
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(&'static str),
    /// Error decoding an incoming message.
    #[error("Message decoding failed: {0}")]
    MessageDecode(#[from] prio::codec::CodecError),
    /// Corresponds to `staleReport`, §3.1
    #[error("Stale report: {0}")]
    StaleReport(Nonce),
    /// Corresponds to `unrecognizedMessage`, §3.1
    #[error("Unrecognized message: {0}")]
    UnrecognizedMessage(&'static str),
    /// Corresponds to `outdatedHpkeConfig`, §3.1
    #[error("Outdated HPKE config: {0}")]
    OutdatedHpkeConfig(HpkeConfigId),
    /// A report was rejected becuase the timestamp is too far in the future,
    /// §4.3.4.
    // TODO(timg): define an error type in §3.1 and clarify language on
    // rejecting future reports
    #[error("Report from the future: {0}")]
    ReportFromTheFuture(Nonce),
}

// This impl allows use of [`Error`] in [`warp::reject::Rejection`]
impl warp::reject::Reject for Error {}

/// A PPM aggregator
#[derive(Clone, Debug)]
pub struct Aggregator<C> {
    /// This aggregator's perception of what time it is
    clock: C,
    /// How much clock skew to allow between client and aggregator. Reports from
    /// farther than this duration into the future will be rejected.
    tolerable_clock_skew: Duration,
    /// Role of this aggregator
    role: Role,
    /// Used to decrypt reports received by this aggregator
    // TODO: Aggregators should have multiple generations of HPKE config
    // available to decrypt tardy reports
    report_recipient: HpkeRecipient,
    /// Reports received by this aggregator
    stored_reports: Arc<Mutex<HashMap<Nonce, Report>>>,
}

impl<C: Clock> Aggregator<C> {
    /// Create a new aggregator. `report_recipient` is used to decrypt reports
    /// received by this aggregator.
    fn new(
        clock: C,
        tolerable_clock_skew: Duration,
        role: Role,
        report_recipient: HpkeRecipient,
    ) -> Result<Self, Error> {
        if tolerable_clock_skew < Duration::zero() {
            return Err(Error::InvalidConfiguration(
                "tolerable clock skew must be positive",
            ));
        }

        Ok(Self {
            clock,
            tolerable_clock_skew,
            role,
            report_recipient,
            stored_reports: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Implements the `/upload` endpoint for the leader, described in §4.2 of
    /// draft-gpew-priv-ppm.
    fn handle_upload(&self, report: &Report) -> Result<(), Error> {
        let mut stored_reports = self.stored_reports.lock().unwrap();

        // §4.2.2 and 4.3.2.2: reject reports whose nonce has been seen before
        if stored_reports.contains_key(&report.nonce) {
            warn!(?report.nonce, "report replayed");
            return Err(Error::StaleReport(report.nonce));
        }

        // §4.2.2 The leader's report is the first one
        if report.encrypted_input_shares.len() != 2 {
            warn!(
                share_count = report.encrypted_input_shares.len(),
                "unexpected number of encrypted shares in report"
            );
            return Err(Error::UnrecognizedMessage(
                "unexpected number of encrypted shares in report",
            ));
        }
        let leader_report = &report.encrypted_input_shares[0];

        // §4.2.2: verify that the report's HPKE config ID is known
        if leader_report.config_id != self.report_recipient.config.id {
            warn!(
                config_id = ?leader_report.config_id,
                "unknown HPKE config ID"
            );
            return Err(Error::OutdatedHpkeConfig(leader_report.config_id));
        }

        let now = self.clock.now();

        // §4.2.4: reject reports from too far in the future
        if report.nonce.time.as_naive_date_time().sub(now) > self.tolerable_clock_skew {
            warn!(?report.nonce, "report timestamp exceeds tolerable clock skew");
            return Err(Error::ReportFromTheFuture(report.nonce));
        }

        // TODO: reject with `staleReport` reports whose timestamps fall in a
        // batch interval that has already been collected (§4.3.2). We don't
        // support collection so we can't implement this requirement yet.

        // Check that we can decrypt the report. This isn't required by the spec
        // but this exercises HPKE decryption and saves us the trouble of
        // storing reports we can't use. We don't inform the client if this
        // fails.
        if let Err(error) = self.report_recipient.open(
            leader_report,
            &Report::associated_data(report.nonce, &report.extensions),
        ) {
            warn!(?report.nonce, ?error, "report decryption failed");
            return Ok(());
        }

        // Store the report
        // TODO: put this in real storage
        stored_reports.insert(report.nonce, report.clone());

        Ok(())
    }
}

/// Injects a clone of the provided value into the warp filter, making it
/// available to the filter's map() or and_then() handler.
fn with_cloned_value<T: Clone + Sync + Send>(
    value: T,
) -> impl Filter<Extract = (T,), Error = Infallible> + Clone {
    warp::any().map(move || value.clone())
}

fn with_decoded_message<T: Decode + Send + Sync>(
) -> impl Filter<Extract = (T,), Error = Rejection> + Clone {
    warp::body::bytes().and_then(|body: Bytes| async move {
        T::get_decoded(&body).map_err(|e| warp::reject::custom(Error::from(e)))
    })
}

/// Constructs a Warp filter with endpoints common to all aggregators.
fn aggregator_filter<C: 'static + Clock>(
    clock: C,
    tolerable_clock_skew: Duration,
    role: Role,
    hpke_recipient: HpkeRecipient,
) -> Result<BoxedFilter<(impl Reply,)>, Error> {
    if !role.is_aggregator() {
        return Err(Error::InvalidConfiguration("role is not an aggregator"));
    }

    let hpke_config_encoded = hpke_recipient.config.get_encoded();

    let aggregator = Aggregator::new(clock, tolerable_clock_skew, role, hpke_recipient)?;

    let hpke_config_endpoint = warp::path("hpke_config")
        .and(warp::get())
        .map(move || {
            reply::with_header(
                reply::with_status(hpke_config_encoded.clone(), StatusCode::OK),
                CACHE_CONTROL,
                "max-age=86400",
            )
        })
        .with(trace::named("hpke_config"));

    let upload_endpoint = warp::path("upload")
        .and(warp::post())
        .and(with_cloned_value(aggregator))
        .and(with_decoded_message())
        .and_then(|aggregator: Aggregator<C>, report: Report| async move {
            // Only the leader supports upload
            if aggregator.role != Role::Leader {
                return Err(warp::reject::not_found());
            }

            aggregator
                .handle_upload(&report)
                .map_err(warp::reject::custom)?;

            Ok(reply::with_status(warp::reply(), StatusCode::OK)) as Result<_, Rejection>
        })
        .with(trace::named("upload"));

    Ok(hpke_config_endpoint.or(upload_endpoint).boxed())
}

/// Construct a PPM aggregator server, listening on the provided [`SocketAddr`].
/// If the `SocketAddr`'s `port` is 0, an ephemeral port is used. Returns a
/// `SocketAddr` representing the address and port the server are listening on
/// and a future that can be `await`ed to begin serving requests.
pub fn aggregator_server<C: 'static + Clock>(
    clock: C,
    tolerable_clock_skew: Duration,
    role: Role,
    hpke_recipient: HpkeRecipient,
    listen_address: SocketAddr,
) -> Result<(SocketAddr, impl Future<Output = ()> + 'static), Error> {
    let routes = aggregator_filter(clock, tolerable_clock_skew, role, hpke_recipient)?;

    Ok(warp::serve(routes).bind_ephemeral(listen_address))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        hpke::{HpkeSender, Label},
        message::{HpkeConfig, TaskId, Time},
        time::tests::MockClock,
        trace::install_subscriber,
    };
    use assert_matches::assert_matches;
    use hyper::body::to_bytes;
    use prio::codec::Decode;
    use std::{io::Cursor, sync::Once};
    use warp::reply::Reply;

    // Install a trace subscriber once for all tests
    static INSTALL_TRACE_SUBSCRIBER: Once = Once::new();

    #[test]
    fn invalid_role() {
        INSTALL_TRACE_SUBSCRIBER.call_once(|| install_subscriber().unwrap());

        let hpke_recipient = HpkeRecipient::generate(
            TaskId::random(),
            Label::InputShare,
            Role::Client,
            Role::Leader,
        );

        for invalid_role in [Role::Collector, Role::Client] {
            assert_matches!(
                aggregator_filter(
                    MockClock::default(),
                    Duration::minutes(10),
                    invalid_role,
                    hpke_recipient.clone(),
                ),
                Err(Error::InvalidConfiguration(_))
            );
        }
    }

    #[test]
    fn invalid_clock_skew() {
        INSTALL_TRACE_SUBSCRIBER.call_once(|| install_subscriber().unwrap());

        let hpke_recipient = HpkeRecipient::generate(
            TaskId::random(),
            Label::InputShare,
            Role::Client,
            Role::Leader,
        );

        assert_matches!(
            Aggregator::new(
                MockClock::default(),
                Duration::minutes(-10),
                Role::Leader,
                hpke_recipient
            ),
            Err(Error::InvalidConfiguration(_))
        );
    }

    #[tokio::test]
    async fn hpke_config() {
        INSTALL_TRACE_SUBSCRIBER.call_once(|| install_subscriber().unwrap());

        let task_id = TaskId::random();

        let hpke_recipient =
            HpkeRecipient::generate(task_id, Label::InputShare, Role::Client, Role::Leader);

        let response = warp::test::request()
            .path("/hpke_config")
            .method("GET")
            .filter(
                &aggregator_filter(
                    MockClock::default(),
                    Duration::minutes(10),
                    Role::Leader,
                    hpke_recipient.clone(),
                )
                .unwrap(),
            )
            .await
            .unwrap()
            .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CACHE_CONTROL).unwrap(),
            "max-age=86400"
        );

        let bytes = to_bytes(response.into_body()).await.unwrap();
        let hpke_config = HpkeConfig::decode(&mut Cursor::new(&bytes)).unwrap();
        let sender = HpkeSender {
            task_id,
            recipient_config: hpke_config,
            label: Label::InputShare,
            sender_role: Role::Client,
            recipient_role: Role::Leader,
        };

        let message = b"this is a message";
        let associated_data = b"some associated data";

        let ciphertext = sender.seal(message, associated_data).unwrap();

        let plaintext = hpke_recipient.open(&ciphertext, associated_data).unwrap();
        assert_eq!(&plaintext, message);
    }

    fn setup_report(clock: &MockClock, skew: Duration) -> (HpkeRecipient, Report) {
        let task_id = TaskId::random();
        let report_time = clock.now() - skew;

        let hpke_recipient =
            HpkeRecipient::generate(task_id, Label::InputShare, Role::Client, Role::Leader);

        let nonce = Nonce {
            time: Time(report_time.timestamp() as u64),
            rand: 0,
        };
        let extensions = vec![];
        let associated_data = Report::associated_data(nonce, &extensions);
        let message = b"this is a message";

        let leader_sender = HpkeSender {
            task_id,
            recipient_config: hpke_recipient.config.clone(),
            label: Label::InputShare,
            sender_role: Role::Client,
            recipient_role: Role::Leader,
        };
        let leader_ciphertext = leader_sender.seal(message, &associated_data).unwrap();

        let helper_sender = HpkeSender {
            task_id,
            recipient_config: hpke_recipient.config.clone(),
            label: Label::InputShare,
            sender_role: Role::Client,
            recipient_role: Role::Helper,
        };
        let helper_ciphertext = helper_sender.seal(message, &associated_data).unwrap();

        let report = Report {
            task_id,
            nonce,
            extensions,
            encrypted_input_shares: vec![leader_ciphertext, helper_ciphertext],
        };

        (hpke_recipient, report)
    }

    #[tokio::test]
    async fn upload_filter() {
        INSTALL_TRACE_SUBSCRIBER.call_once(|| install_subscriber().unwrap());

        let clock = MockClock::default();
        let skew = Duration::minutes(10);

        let (report_recipient, report) = setup_report(&clock, skew);
        let filter = aggregator_filter(clock, skew, Role::Leader, report_recipient).unwrap();

        let response = warp::test::request()
            .method("POST")
            .path("/upload")
            .body(report.get_encoded())
            .filter(&filter)
            .await
            .unwrap()
            .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(to_bytes(response.into_body()).await.unwrap().is_empty())

        // TODO: add tests for error conditions verifying we get expected problem
        // document
    }

    // Helper should not expose /upload endpoint
    #[tokio::test]
    async fn upload_filter_helper() {
        INSTALL_TRACE_SUBSCRIBER.call_once(|| install_subscriber().unwrap());

        let clock = MockClock::default();
        let skew = Duration::minutes(10);

        let (report_recipient, report) = setup_report(&clock, skew);

        let filter = aggregator_filter(clock, skew, Role::Helper, report_recipient).unwrap();

        let result = warp::test::request()
            .method("POST")
            .path("/upload")
            .body(report.get_encoded())
            .filter(&filter)
            .await;

        // We can't use `Result::unwrap_err` or `assert_matches!` here because
        //  `impl Reply` is not `Debug`
        if let Err(rejection) = result {
            assert!(rejection.is_not_found());
        } else {
            panic!("should get rejection");
        }
    }

    fn setup_upload_test(skew: Duration) -> (Aggregator<MockClock>, Report) {
        let clock = MockClock::default();
        let (report_recipient, report) = setup_report(&clock, skew);
        let aggregator = Aggregator::new(clock, skew, Role::Leader, report_recipient).unwrap();

        (aggregator, report)
    }

    #[test]
    fn upload() {
        INSTALL_TRACE_SUBSCRIBER.call_once(|| install_subscriber().unwrap());

        let skew = Duration::minutes(10);
        let (aggregator, report) = setup_upload_test(skew);

        aggregator.handle_upload(&report).unwrap();

        assert_eq!(
            aggregator
                .stored_reports
                .lock()
                .unwrap()
                .get(&report.nonce)
                .unwrap(),
            &report
        );

        // should reject duplicate reports
        assert_matches!(aggregator.handle_upload(&report), Err(Error::StaleReport(stale_nonce)) => {
            assert_eq!(report.nonce, stale_nonce);
        });
    }

    #[test]
    fn upload_wrong_number_of_encrypted_shares() {
        INSTALL_TRACE_SUBSCRIBER.call_once(|| install_subscriber().unwrap());

        let skew = Duration::minutes(10);
        let (aggregator, mut report) = setup_upload_test(skew);

        report.encrypted_input_shares = vec![report.encrypted_input_shares[0].clone()];

        assert_matches!(
            aggregator.handle_upload(&report),
            Err(Error::UnrecognizedMessage(_))
        );
    }

    #[test]
    fn upload_wrong_hpke_config_id() {
        INSTALL_TRACE_SUBSCRIBER.call_once(|| install_subscriber().unwrap());

        let skew = Duration::minutes(10);
        let (aggregator, mut report) = setup_upload_test(skew);

        report.encrypted_input_shares[0].config_id = HpkeConfigId(101);

        assert_matches!(aggregator.handle_upload(&report), Err(Error::OutdatedHpkeConfig(config_id)) => {
            assert_eq!(config_id, HpkeConfigId(101));
        });
    }

    fn reencrypt_report(report: Report, hpke_recipient: &HpkeRecipient) -> Report {
        let associated_data = Report::associated_data(report.nonce, &report.extensions);
        let message = b"this is a message";

        let leader_sender = HpkeSender {
            task_id: report.task_id,
            recipient_config: hpke_recipient.config.clone(),
            label: Label::InputShare,
            sender_role: Role::Client,
            recipient_role: Role::Leader,
        };
        let leader_ciphertext = leader_sender.seal(message, &associated_data).unwrap();

        let helper_sender = HpkeSender {
            task_id: report.task_id,
            recipient_config: hpke_recipient.config.clone(),
            label: Label::InputShare,
            sender_role: Role::Client,
            recipient_role: Role::Helper,
        };
        let helper_ciphertext = helper_sender.seal(message, &associated_data).unwrap();

        Report {
            task_id: report.task_id,
            nonce: report.nonce,
            extensions: report.extensions,
            encrypted_input_shares: vec![leader_ciphertext, helper_ciphertext],
        }
    }

    #[test]
    fn report_in_the_future() {
        INSTALL_TRACE_SUBSCRIBER.call_once(|| install_subscriber().unwrap());

        let skew = Duration::minutes(10);
        let (aggregator, mut report) = setup_upload_test(skew);

        // Boundary condition
        report.nonce.time = Time::from_naive_date_time(aggregator.clock.now() + skew);
        let mut report = reencrypt_report(report, &aggregator.report_recipient);
        aggregator.handle_upload(&report).unwrap();

        assert!(aggregator
            .stored_reports
            .lock()
            .unwrap()
            .contains_key(&report.nonce));

        // Just past the clock skew
        report.nonce.time =
            Time::from_naive_date_time(aggregator.clock.now() + skew + Duration::seconds(1));
        let report = reencrypt_report(report, &aggregator.report_recipient);
        assert_matches!(aggregator.handle_upload(&report), Err(Error::ReportFromTheFuture(nonce)) => {
            assert_eq!(report.nonce, nonce);
        });
    }
}
