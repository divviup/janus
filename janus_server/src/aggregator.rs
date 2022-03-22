//! Common functionality for PPM aggregators
use crate::{
    datastore::{self, Datastore},
    hpke::HpkeRecipient,
    message::{HpkeConfigId, Nonce, Report, Role},
    time::Clock,
};
use bytes::Bytes;
use chrono::Duration;
use http::{header::CACHE_CONTROL, StatusCode};
use prio::codec::{Decode, Encode};
use std::{convert::Infallible, future::Future, net::SocketAddr, ops::Sub, sync::Arc};
use tracing::warn;
use warp::{filters::BoxedFilter, reply, trace, Filter, Rejection, Reply};

/// Errors returned by functions and methods in this module
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An invalid configuration was passed.
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(&'static str),
    /// Error decoding an incoming message.
    #[error("message decoding failed: {0}")]
    MessageDecode(#[from] prio::codec::CodecError),
    /// Corresponds to `staleReport`, §3.1
    #[error("stale report: {0}")]
    StaleReport(Nonce),
    /// Corresponds to `unrecognizedMessage`, §3.1
    #[error("unrecognized message: {0}")]
    UnrecognizedMessage(&'static str),
    /// Corresponds to `outdatedHpkeConfig`, §3.1
    #[error("outdated HPKE config: {0}")]
    OutdatedHpkeConfig(HpkeConfigId),
    /// A report was rejected becuase the timestamp is too far in the future,
    /// §4.3.4.
    // TODO(timg): define an error type in §3.1 and clarify language on
    // rejecting future reports
    #[error("report from the future: {0}")]
    ReportFromTheFuture(Nonce),
    #[error("datastore error: {0}")]
    Datastore(#[from] datastore::Error),
}

// This impl allows use of [`Error`] in [`warp::reject::Rejection`]
impl warp::reject::Reject for Error {}

/// A PPM aggregator
#[derive(Clone, derivative::Derivative)]
#[derivative(Debug)]
pub struct Aggregator<C> {
    #[derivative(Debug = "ignore")]
    /// The datstore used for durable storage.
    datastore: Arc<Datastore>,
    /// The clock to use to sample time.
    clock: C,
    /// How much clock skew to allow between client and aggregator. Reports from
    /// farther than this duration into the future will be rejected.
    tolerable_clock_skew: Duration,
    /// Role of this aggregator.
    role: Role,
    /// Used to decrypt reports received by this aggregator.
    // TODO: Aggregators should have multiple generations of HPKE config
    // available to decrypt tardy reports
    report_recipient: HpkeRecipient,
}

impl<C: Clock> Aggregator<C> {
    /// Create a new aggregator. `report_recipient` is used to decrypt reports
    /// received by this aggregator.
    fn new(
        datastore: Arc<Datastore>,
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
            datastore,
            clock,
            tolerable_clock_skew,
            role,
            report_recipient,
        })
    }

    /// Implements the `/upload` endpoint for the leader, described in §4.2 of
    /// draft-gpew-priv-ppm.
    async fn handle_upload(&self, report: &Report) -> Result<(), Error> {
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
            warn!(?report.task_id, ?report.nonce, "report timestamp exceeds tolerable clock skew");
            return Err(Error::ReportFromTheFuture(report.nonce));
        }

        // Check that we can decrypt the report. This isn't required by the spec
        // but this exercises HPKE decryption and saves us the trouble of
        // storing reports we can't use. We don't inform the client if this
        // fails.
        if let Err(error) = self.report_recipient.open(
            leader_report,
            &Report::associated_data(report.nonce, &report.extensions),
        ) {
            warn!(?report.task_id, ?report.nonce, ?error, "report decryption failed");
            return Ok(());
        }

        self.datastore
            .run_tx(|tx| {
                let report = report.clone();
                Box::pin(async move {
                    // §4.2.2 and 4.3.2.2: reject reports whose nonce has been seen before
                    match tx
                        .get_client_report_by_task_id_and_nonce(report.task_id, report.nonce)
                        .await
                    {
                        Ok(_) => {
                            warn!(?report.task_id, ?report.nonce, "report replayed");
                            return Err(datastore::Error::User(
                                Error::StaleReport(report.nonce).into(),
                            ));
                        }

                        Err(datastore::Error::NotFound) => (), // happy path

                        Err(err) => return Err(err),
                    };

                    // TODO: reject with `staleReport` reports whose timestamps fall in a
                    // batch interval that has already been collected (§4.3.2). We don't
                    // support collection so we can't implement this requirement yet.

                    // Store the report.
                    tx.put_client_report(&report).await?;
                    Ok(())
                })
            })
            .await
            .map_err(downcast_to_aggregator_error)?;
        Ok(())
    }
}

fn downcast_to_aggregator_error(err: datastore::Error) -> Error {
    match err {
        datastore::Error::User(err) => match err.downcast::<Error>() {
            Ok(err) => *err,
            Err(err) => Error::Datastore(datastore::Error::User(err)),
        },
        _ => Error::Datastore(err),
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
    datastore: Arc<Datastore>,
    clock: C,
    tolerable_clock_skew: Duration,
    role: Role,
    hpke_recipient: HpkeRecipient,
) -> Result<BoxedFilter<(impl Reply,)>, Error> {
    if !role.is_aggregator() {
        return Err(Error::InvalidConfiguration("role is not an aggregator"));
    }

    let hpke_config_encoded = hpke_recipient.config.get_encoded();

    let aggregator = Aggregator::new(datastore, clock, tolerable_clock_skew, role, hpke_recipient)?;

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
                .await
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
    datastore: Arc<Datastore>,
    clock: C,
    tolerable_clock_skew: Duration,
    role: Role,
    hpke_recipient: HpkeRecipient,
    listen_address: SocketAddr,
) -> Result<(SocketAddr, impl Future<Output = ()> + 'static), Error> {
    let routes = aggregator_filter(datastore, clock, tolerable_clock_skew, role, hpke_recipient)?;

    Ok(warp::serve(routes).bind_ephemeral(listen_address))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        datastore::test_util::{ephemeral_datastore, DbHandle},
        hpke::{HpkeSender, Label},
        message::{HpkeConfig, TaskId, Time},
        time::tests::MockClock,
        trace::test_util::install_trace_subscriber,
    };
    use assert_matches::assert_matches;
    use hyper::body::to_bytes;
    use prio::codec::Decode;
    use std::io::Cursor;
    use warp::reply::Reply;

    #[tokio::test]
    async fn invalid_role() {
        install_trace_subscriber();

        let (datastore, _db_handle) = ephemeral_datastore().await;
        let datastore = Arc::new(datastore);
        let hpke_recipient = HpkeRecipient::generate(
            TaskId::random(),
            Label::InputShare,
            Role::Client,
            Role::Leader,
        );

        for invalid_role in [Role::Collector, Role::Client] {
            assert_matches!(
                aggregator_filter(
                    datastore.clone(),
                    MockClock::default(),
                    Duration::minutes(10),
                    invalid_role,
                    hpke_recipient.clone(),
                ),
                Err(Error::InvalidConfiguration(_))
            );
        }
    }

    #[tokio::test]
    async fn invalid_clock_skew() {
        install_trace_subscriber();

        let (datastore, _db_handle) = ephemeral_datastore().await;
        let hpke_recipient = HpkeRecipient::generate(
            TaskId::random(),
            Label::InputShare,
            Role::Client,
            Role::Leader,
        );

        assert_matches!(
            Aggregator::new(
                Arc::new(datastore),
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
        install_trace_subscriber();

        let task_id = TaskId::random();
        let (datastore, _db_handle) = ephemeral_datastore().await;
        let hpke_recipient =
            HpkeRecipient::generate(task_id, Label::InputShare, Role::Client, Role::Leader);

        let response = warp::test::request()
            .path("/hpke_config")
            .method("GET")
            .filter(
                &aggregator_filter(
                    Arc::new(datastore),
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

    async fn setup_report(
        datastore: &Datastore,
        clock: &MockClock,
        skew: Duration,
    ) -> (HpkeRecipient, Report) {
        let task_id = TaskId::random();

        datastore
            .run_tx(|tx| Box::pin(async move { tx.put_task(task_id).await }))
            .await
            .unwrap();

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
        install_trace_subscriber();

        let (datastore, _db_handle) = ephemeral_datastore().await;
        let clock = MockClock::default();
        let skew = Duration::minutes(10);

        let (report_recipient, report) = setup_report(&datastore, &clock, skew).await;
        let filter = aggregator_filter(
            Arc::new(datastore),
            clock,
            skew,
            Role::Leader,
            report_recipient,
        )
        .unwrap();

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
        install_trace_subscriber();

        let (datastore, _db_handle) = ephemeral_datastore().await;
        let clock = MockClock::default();
        let skew = Duration::minutes(10);

        let (report_recipient, report) = setup_report(&datastore, &clock, skew).await;

        let filter = aggregator_filter(
            Arc::new(datastore),
            clock,
            skew,
            Role::Helper,
            report_recipient,
        )
        .unwrap();

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

    async fn setup_upload_test(
        skew: Duration,
    ) -> (Aggregator<MockClock>, Report, Arc<Datastore>, DbHandle) {
        let (datastore, db_handle) = ephemeral_datastore().await;
        let datastore = Arc::new(datastore);
        let clock = MockClock::default();
        let (report_recipient, report) = setup_report(&datastore, &clock, skew).await;

        let aggregator = Aggregator::new(
            datastore.clone(),
            clock,
            skew,
            Role::Leader,
            report_recipient,
        )
        .unwrap();

        (aggregator, report, datastore, db_handle)
    }

    #[tokio::test]
    async fn upload() {
        install_trace_subscriber();

        let skew = Duration::minutes(10);
        let (aggregator, report, datastore, _db_handle) = setup_upload_test(skew).await;

        aggregator.handle_upload(&report).await.unwrap();

        let got_report = datastore
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.get_client_report_by_task_id_and_nonce(report.task_id, report.nonce)
                        .await
                })
            })
            .await
            .unwrap();
        assert_eq!(report, got_report);

        // should reject duplicate reports
        assert_matches!(aggregator.handle_upload(&report).await, Err(Error::StaleReport(stale_nonce)) => {
            assert_eq!(report.nonce, stale_nonce);
        });
    }

    #[tokio::test]
    async fn upload_wrong_number_of_encrypted_shares() {
        install_trace_subscriber();

        let skew = Duration::minutes(10);
        let (aggregator, mut report, _, _db_handle) = setup_upload_test(skew).await;

        report.encrypted_input_shares = vec![report.encrypted_input_shares[0].clone()];

        assert_matches!(
            aggregator.handle_upload(&report).await,
            Err(Error::UnrecognizedMessage(_))
        );
    }

    #[tokio::test]
    async fn upload_wrong_hpke_config_id() {
        install_trace_subscriber();

        let skew = Duration::minutes(10);
        let (aggregator, mut report, _, _db_handle) = setup_upload_test(skew).await;

        report.encrypted_input_shares[0].config_id = HpkeConfigId(101);

        assert_matches!(aggregator.handle_upload(&report).await, Err(Error::OutdatedHpkeConfig(config_id)) => {
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

    #[tokio::test]
    async fn report_in_the_future() {
        install_trace_subscriber();

        let skew = Duration::minutes(10);
        let (aggregator, mut report, datastore, _db_handle) = setup_upload_test(skew).await;

        // Boundary condition
        report.nonce.time = Time::from_naive_date_time(aggregator.clock.now() + skew);
        let mut report = reencrypt_report(report, &aggregator.report_recipient);
        aggregator.handle_upload(&report).await.unwrap();

        let got_report = datastore
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.get_client_report_by_task_id_and_nonce(report.task_id, report.nonce)
                        .await
                })
            })
            .await
            .unwrap();
        assert_eq!(report, got_report);

        // Just past the clock skew
        report.nonce.time =
            Time::from_naive_date_time(aggregator.clock.now() + skew + Duration::seconds(1));
        let report = reencrypt_report(report, &aggregator.report_recipient);
        assert_matches!(aggregator.handle_upload(&report).await, Err(Error::ReportFromTheFuture(nonce)) => {
            assert_eq!(report.nonce, nonce);
        });
    }
}
