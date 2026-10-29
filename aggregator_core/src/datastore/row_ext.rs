//! Extension trait for [`tokio_postgres::row::Row`].

use std::{
    convert::TryFrom,
    fmt::{Debug, Display},
    io::Cursor,
};

use chrono::{NaiveDateTime, TimeDelta};
use janus_core::{
    hpke::{self, HpkePrivateKey},
    time::TimeExt,
    vdaf::VdafInstance,
};
use janus_messages::{
    AggregateShareId, AggregationJobId, CollectionJobId, CollectionJobReq, Duration, Extension,
    HpkeCiphertext, HpkeConfig, Query, ReportId, ReportIdChecksum, ReportMetadata, Role,
    TaskConfiguration, TaskId, Time, TimePrecision, VerifyContinue, VerifyInit, VerifyResp,
    batch_mode::BatchMode,
};
use postgres_types::{FromSql, Json};
use prio::{
    codec::{Decode, Encode, ParameterizedDecode, decode_u16_items},
    topology::ping_pong::PingPongContinuation,
};
use tokio_postgres::row::{Row, RowIndex};
use url::Url;

use crate::{
    AsyncAggregator, SecretBytes,
    datastore::{
        Crypter, Error,
        models::{
            AggregateShareJob, AggregationJob, AggregatorRole, AuthenticationTokenType,
            BatchAggregation, BatchAggregationState, BatchAggregationStateCode, CollectionJob,
            CollectionJobState, CollectionJobStateCode, HpkeKeypair, LeaderStoredReport,
            ReportAggregation, ReportAggregationState, ReportAggregationStateCode, SqlInterval,
        },
    },
    task::{self, AggregationMode, AggregatorTask, AggregatorTaskParameters},
    taskprov::PeerAggregator,
};

/// Extensions for [`tokio_postgres::row::Row`]
pub(super) trait RowExt {
    /// Get an integer of type `P` from the row, then attempt to convert it to the desired integer
    /// type `T`.
    fn get_postgres_integer_and_convert<'a, P, I, T>(&'a self, idx: I) -> Result<T, Error>
    where
        P: FromSql<'a>,
        I: RowIndex + Display,
        T: TryFrom<P, Error = std::num::TryFromIntError>;

    /// Get a PostgreSQL `BIGINT` from the row, which is represented in Rust as
    /// i64 ([1]), then attempt to convert it to the desired integer type `T`.
    ///
    /// [1]: https://docs.rs/postgres-types/latest/postgres_types/trait.FromSql.html
    fn get_bigint_and_convert<I, T>(&self, idx: I) -> Result<T, Error>
    where
        I: RowIndex + Display,
        T: TryFrom<i64, Error = std::num::TryFromIntError>,
    {
        self.get_postgres_integer_and_convert::<i64, I, T>(idx)
    }

    /// Like [`Self::get_bigint_and_convert`] but handles nullable columns.
    fn get_nullable_bigint_and_convert<I, T>(&self, idx: I) -> Result<Option<T>, Error>
    where
        I: RowIndex + Display,
        T: TryFrom<i64, Error = std::num::TryFromIntError>;

    /// Get a PostgreSQL `BYTEA` from the row and attempt to convert it to `T`.
    fn get_bytea_and_convert<T>(&self, idx: &'static str) -> Result<T, Error>
    where
        for<'a> T: TryFrom<&'a [u8]>,
        for<'a> <T as TryFrom<&'a [u8]>>::Error: Debug;

    /// Like [`Self::get_bytea_and_convert`] but handles nullable columns.
    fn get_nullable_bytea_and_convert<T>(&self, idx: &'static str) -> Result<Option<T>, Error>
    where
        for<'a> T: TryFrom<&'a [u8]>,
        for<'a> <T as TryFrom<&'a [u8]>>::Error: Debug;

    /// Get a PostgreSQL `BYTEA` from the row and attempt to decode a `T` value from it.
    fn get_bytea_and_decode<T, P>(
        &self,
        idx: &'static str,
        decoding_parameter: &P,
    ) -> Result<T, Error>
    where
        T: ParameterizedDecode<P>;

    /// Construct an [`AggregatorTask`] from the contents of the row.
    fn task(&self, crypter: &Crypter, task_id: &TaskId) -> Result<AggregatorTask, Error>;

    /// Construct a [`LeaderStoredReport`] from the contents of the row.
    fn client_report<const SEED_SIZE: usize, A: AsyncAggregator<SEED_SIZE>>(
        &self,
        vdaf: &A,
        task_id: TaskId,
        report_id: ReportId,
    ) -> Result<LeaderStoredReport<SEED_SIZE, A>, Error>;

    /// Construct an [`AggregationJob`] from the contents of the row.
    fn aggregation_job<const SEED_SIZE: usize, B, A>(
        &self,
        task_id: &TaskId,
        aggregation_job_id: &AggregationJobId,
    ) -> Result<AggregationJob<SEED_SIZE, B, A>, Error>
    where
        B: BatchMode,
        A: AsyncAggregator<SEED_SIZE>;

    /// Construct a [`ReportAggregation`] from the contents of the row.
    fn report_aggregation<const SEED_SIZE: usize, A>(
        &self,
        vdaf: &A,
        role: &Role,
        task_id: &TaskId,
        aggregation_job_id: &AggregationJobId,
        report_id: &ReportId,
        time_precision: TimePrecision,
    ) -> Result<ReportAggregation<SEED_SIZE, A>, Error>
    where
        A: AsyncAggregator<SEED_SIZE>;

    /// Construct a [`CollectionJob`] from the contents of the row.
    fn collection_job<const SEED_SIZE: usize, B, A>(
        &self,
        vdaf: &A,
        task_id: TaskId,
        batch_identifier: B::BatchIdentifier,
        collection_job_id: CollectionJobId,
    ) -> Result<CollectionJob<SEED_SIZE, B, A>, Error>
    where
        B: BatchMode,
        A: AsyncAggregator<SEED_SIZE>;

    /// Construct a [`BatchAggregation`] from the contents of the row.
    fn batch_aggregation<const SEED_SIZE: usize, B, A>(
        &self,
        vdaf: &A,
        task_id: TaskId,
        batch_identifier: B::BatchIdentifier,
        aggregation_param: A::AggregationParam,
        ord: u64,
    ) -> Result<BatchAggregation<SEED_SIZE, B, A>, Error>
    where
        B: BatchMode,
        A: AsyncAggregator<SEED_SIZE>;

    /// Construct an [`AggregateShareJob`] from the contents of the row.
    fn aggregate_share_job<const SEED_SIZE: usize, B, A>(
        &self,
        vdaf: &A,
        task_id: &TaskId,
        batch_identifier: B::BatchIdentifier,
        aggregation_param: A::AggregationParam,
    ) -> Result<AggregateShareJob<SEED_SIZE, B, A>, Error>
    where
        B: BatchMode,
        A: AsyncAggregator<SEED_SIZE>;

    /// Construct an [`HpkeKeypair`] from the contents of the row.
    fn hpke_keypair(&self, crypter: &Crypter) -> Result<HpkeKeypair, Error>;

    /// Construct a [`PeerAggregator`] from the contents of the rows.
    fn taskprov_peer_aggregator(
        &self,
        crypter: &Crypter,
        aggregator_auth_token_rows: &[Row],
        collector_auth_token_rows: &[Row],
    ) -> Result<PeerAggregator, Error>;
}

impl RowExt for Row {
    fn get_postgres_integer_and_convert<'a, P, I, T>(&'a self, idx: I) -> Result<T, Error>
    where
        P: FromSql<'a>,
        I: RowIndex + Display,
        T: TryFrom<P, Error = std::num::TryFromIntError>,
    {
        let postgres_integer: P = self.get(idx);
        Ok(T::try_from(postgres_integer)?)
    }

    fn get_nullable_bigint_and_convert<I, T>(&self, idx: I) -> Result<Option<T>, Error>
    where
        I: RowIndex + Display,
        T: TryFrom<i64, Error = std::num::TryFromIntError>,
    {
        let bigint: Option<i64> = self.get(idx);
        Ok(bigint.map(|bigint| T::try_from(bigint)).transpose()?)
    }

    fn get_bytea_and_convert<T>(&self, idx: &'static str) -> Result<T, Error>
    where
        for<'a> T: TryFrom<&'a [u8]>,
        for<'a> <T as TryFrom<&'a [u8]>>::Error: Debug,
    {
        let encoded: Vec<u8> = self.get(idx);
        T::try_from(&encoded)
            .map_err(|err| Error::DbState(format!("{idx} stored in database is invalid: {err:?}")))
    }

    fn get_nullable_bytea_and_convert<T>(&self, idx: &'static str) -> Result<Option<T>, Error>
    where
        for<'a> T: TryFrom<&'a [u8]>,
        for<'a> <T as TryFrom<&'a [u8]>>::Error: Debug,
    {
        let encoded: Option<Vec<u8>> = self.get(idx);
        encoded
            .map(|encoded| {
                T::try_from(&encoded).map_err(|err| {
                    Error::DbState(format!("{idx} stored in database is invalid: {err:?}"))
                })
            })
            .transpose()
    }

    fn get_bytea_and_decode<T, P>(
        &self,
        idx: &'static str,
        decoding_parameter: &P,
    ) -> Result<T, Error>
    where
        T: ParameterizedDecode<P>,
    {
        let encoded: Vec<u8> = self.get(idx);
        T::get_decoded_with_param(decoding_parameter, &encoded)
            .map_err(|err| Error::DbState(format!("{idx} stored in database is invalid: {err:?}")))
    }

    fn task(&self, crypter: &Crypter, task_id: &TaskId) -> Result<AggregatorTask, Error> {
        // Scalar task parameters.
        let aggregator_role: AggregatorRole = self.get("aggregator_role");
        let peer_aggregator_endpoint = self.get::<_, String>("peer_aggregator_endpoint").parse()?;
        let own_aggregator_endpoint = self.get::<_, String>("own_aggregator_endpoint").parse()?;
        let task_config = TaskConfiguration::get_decoded(self.try_get("task_config")?)?;
        let batch_mode = self.try_get::<_, Json<task::BatchMode>>("batch_mode")?.0;
        let aggregation_mode: Option<AggregationMode> = self.get("aggregation_mode");
        let vdaf = self.try_get::<_, Json<VdafInstance>>("vdaf")?.0;
        let time_precision =
            TimePrecision::from_seconds(self.get_bigint_and_convert("time_precision")?);
        let task_start = self
            .get_nullable_bigint_and_convert("task_start")?
            .map(Time::from_time_precision_units);
        let task_duration = self
            .get_nullable_bigint_and_convert("task_duration")?
            .map(Duration::from_time_precision_units);
        let task_interval = task::reconstruct_task_interval(task_start, task_duration)
            .map_err(|e| Error::DbState(format!("task self has invalid validity interval: {e}")))?;
        let report_expiry_age = self
            .get_nullable_bigint_and_convert("report_expiry_age")?
            .map(|s| Duration::from_seconds(s, &time_precision));
        let min_batch_size = self.get_bigint_and_convert("min_batch_size")?;
        let tolerable_clock_skew = Duration::from_seconds(
            self.get_bigint_and_convert("tolerable_clock_skew")?,
            &time_precision,
        );
        let collector_hpke_config = self
            .get::<_, Option<Vec<u8>>>("collector_hpke_config")
            .map(|config| HpkeConfig::get_decoded(&config))
            .transpose()?;
        let encrypted_vdaf_verify_key: Vec<u8> = self.get("vdaf_verify_key");
        let vdaf_verify_key = crypter
            .decrypt(
                "tasks",
                task_id.as_ref(),
                "vdaf_verify_key",
                &encrypted_vdaf_verify_key,
            )
            .map(SecretBytes::new)?;
        let task_info: Vec<u8> = self.get("task_info");
        // Stored as a naive UTC timestamp.
        let deactivate_at = self
            .get::<_, Option<NaiveDateTime>>("deactivate_at")
            .map(|dt| dt.and_utc());

        let aggregator_auth_token_type: Option<AuthenticationTokenType> =
            self.get("aggregator_auth_token_type");

        let aggregator_auth_token = self
            .get::<_, Option<Vec<u8>>>("aggregator_auth_token")
            .zip(aggregator_auth_token_type)
            .map(|(encrypted_token, token_type)| {
                token_type.as_authentication(&crypter.decrypt(
                    "tasks",
                    task_id.as_ref(),
                    "aggregator_auth_token",
                    &encrypted_token,
                )?)
            })
            .transpose()?;

        let aggregator_auth_token_hash = self
            .get::<_, Option<Vec<u8>>>("aggregator_auth_token_hash")
            .zip(aggregator_auth_token_type)
            .map(|(token_hash, token_type)| token_type.as_authentication_token_hash(&token_hash))
            .transpose()?;

        let collector_auth_token_hash = self
            .get::<_, Option<Vec<u8>>>("collector_auth_token_hash")
            .zip(self.get::<_, Option<AuthenticationTokenType>>("collector_auth_token_type"))
            .map(|(token_hash, token_type)| token_type.as_authentication_token_hash(&token_hash))
            .transpose()?;

        let aggregator_parameters = match (
            aggregator_role,
            aggregation_mode,
            aggregator_auth_token,
            aggregator_auth_token_hash,
            collector_auth_token_hash,
            collector_hpke_config,
        ) {
            (
                AggregatorRole::Leader,
                None,
                Some(aggregator_auth_token),
                None,
                Some(collector_auth_token_hash),
                Some(collector_hpke_config),
            ) => AggregatorTaskParameters::Leader {
                aggregator_auth_token,
                collector_auth_token_hash,
                collector_hpke_config,
            },
            (
                AggregatorRole::Helper,
                Some(aggregation_mode),
                None,
                Some(aggregator_auth_token_hash),
                None,
                Some(collector_hpke_config),
            ) => AggregatorTaskParameters::Helper {
                aggregator_auth_token_hash,
                collector_hpke_config,
                aggregation_mode,
            },
            (AggregatorRole::Helper, Some(aggregation_mode), None, None, None, None) => {
                AggregatorTaskParameters::TaskprovHelper { aggregation_mode }
            }
            values => {
                return Err(Error::DbState(format!(
                    "found task row with unexpected combination of values {values:?}",
                )));
            }
        };

        Ok(AggregatorTask::new_with_task_config(
            *task_id,
            peer_aggregator_endpoint,
            own_aggregator_endpoint,
            batch_mode,
            vdaf,
            vdaf_verify_key,
            task_interval,
            report_expiry_age,
            min_batch_size,
            time_precision,
            tolerable_clock_skew,
            task_info,
            aggregator_parameters,
            task_config,
        )?
        .with_deactivate_at(deactivate_at))
    }

    fn client_report<const SEED_SIZE: usize, A: AsyncAggregator<SEED_SIZE>>(
        &self,
        vdaf: &A,
        task_id: TaskId,
        report_id: ReportId,
    ) -> Result<LeaderStoredReport<SEED_SIZE, A>, Error> {
        let time =
            Time::from_time_precision_units(self.get_bigint_and_convert("client_timestamp")?);

        let encoded_public_extensions: Vec<u8> = self
            .get::<_, Option<_>>("public_extensions")
            .ok_or_else(|| Error::Scrubbed)?;
        let public_extensions: Vec<Extension> =
            decode_u16_items(&(), &mut Cursor::new(&encoded_public_extensions))?;

        let encoded_public_share: Vec<u8> = self
            .get::<_, Option<_>>("public_share")
            .ok_or_else(|| Error::Scrubbed)?;
        let public_share = A::PublicShare::get_decoded_with_param(vdaf, &encoded_public_share)?;

        let encoded_leader_private_extensions: Vec<u8> = self
            .get::<_, Option<_>>("leader_private_extensions")
            .ok_or_else(|| Error::Scrubbed)?;
        let leader_private_extensions: Vec<Extension> =
            decode_u16_items(&(), &mut Cursor::new(&encoded_leader_private_extensions))?;

        let encoded_leader_input_share: Vec<u8> = self
            .get::<_, Option<_>>("leader_input_share")
            .ok_or_else(|| Error::Scrubbed)?;
        let leader_input_share = A::InputShare::get_decoded_with_param(
            &(vdaf, Role::Leader.index().unwrap()),
            &encoded_leader_input_share,
        )?;

        let encoded_helper_input_share: Vec<u8> = self
            .get::<_, Option<_>>("helper_encrypted_input_share")
            .ok_or_else(|| Error::Scrubbed)?;
        let helper_encrypted_input_share =
            HpkeCiphertext::get_decoded(&encoded_helper_input_share)?;

        Ok(LeaderStoredReport::new(
            task_id,
            ReportMetadata::new(report_id, time, public_extensions),
            public_share,
            leader_private_extensions,
            leader_input_share,
            helper_encrypted_input_share,
        ))
    }

    fn aggregation_job<const SEED_SIZE: usize, B, A>(
        &self,
        task_id: &TaskId,
        aggregation_job_id: &AggregationJobId,
    ) -> Result<AggregationJob<SEED_SIZE, B, A>, Error>
    where
        B: BatchMode,
        A: AsyncAggregator<SEED_SIZE>,
    {
        let client_timestamp_interval = self
            .get::<_, SqlInterval>("client_timestamp_interval")
            .into();

        let mut job = AggregationJob::new(
            *task_id,
            *aggregation_job_id,
            A::AggregationParam::get_decoded(self.get("aggregation_param"))?,
            B::PartialBatchIdentifier::get_decoded(self.get::<_, &[u8]>("batch_id"))?,
            client_timestamp_interval,
            self.get("state"),
            self.get_postgres_integer_and_convert::<i32, _, _>("step")?,
        );

        if let Some(hash) = self.get::<_, Option<Vec<u8>>>("last_request_hash") {
            job = job.with_last_request_hash(hash.try_into().map_err(|h| {
                Error::DbState(format!(
                    "last_request_hash value {h:?} cannot be converted to 32 byte array"
                ))
            })?);
        }

        Ok(job)
    }

    fn report_aggregation<const SEED_SIZE: usize, A>(
        &self,
        vdaf: &A,
        role: &Role,
        task_id: &TaskId,
        aggregation_job_id: &AggregationJobId,
        report_id: &ReportId,
        time_precision: TimePrecision,
    ) -> Result<ReportAggregation<SEED_SIZE, A>, Error>
    where
        A: AsyncAggregator<SEED_SIZE>,
    {
        let ord: u64 = self.get_bigint_and_convert("ord")?;
        let time = Time::from_date_time(self.get("client_timestamp"), time_precision);
        let state: ReportAggregationStateCode = self.get("state");
        let error_code: Option<i16> = self.get("error_code");
        let last_verify_resp_bytes: Option<Vec<u8>> = self.get("last_verify_resp");

        let last_verify_resp = last_verify_resp_bytes
            .map(|bytes| VerifyResp::get_decoded(&bytes))
            .transpose()?;

        let agg_state = match state {
            ReportAggregationStateCode::Init => {
                let public_extensions_bytes = self
                    .get::<_, Option<Vec<u8>>>("public_extensions")
                    .ok_or_else(|| {
                    Error::DbState(
                        "report aggregation in state INIT but public_extensions is NULL"
                            .to_string(),
                    )
                })?;
                let public_share_bytes = self
                    .get::<_, Option<Vec<u8>>>("public_share")
                    .ok_or_else(|| {
                        Error::DbState(
                            "report aggregation in state INIT but public_share is NULL".to_string(),
                        )
                    })?;
                let leader_private_extensions_bytes = self
                    .get::<_, Option<Vec<u8>>>("leader_private_extensions")
                    .ok_or_else(|| {
                        Error::DbState(
                            "report aggregation in state INIT but leader_private_extensions is NULL"
                                .to_string(),
                        )
                    })?;
                let leader_input_share_bytes = self
                    .get::<_, Option<Vec<u8>>>("leader_input_share")
                    .ok_or_else(|| {
                        Error::DbState(
                            "report aggregation in state INIT but leader_input_share is NULL"
                                .to_string(),
                        )
                    })?;
                let helper_encrypted_input_share_bytes =
                    self.get::<_, Option<Vec<u8>>>("helper_encrypted_input_share")
                        .ok_or_else(|| {
                            Error::DbState(
                            "report aggregation in state INIT but helper_encrypted_input_share is NULL"
                                .to_string(),
                        )
                        })?;

                let public_extensions =
                    decode_u16_items(&(), &mut Cursor::new(&public_extensions_bytes))?;
                let public_share =
                    A::PublicShare::get_decoded_with_param(vdaf, &public_share_bytes)?;
                let leader_private_extensions =
                    decode_u16_items(&(), &mut Cursor::new(&leader_private_extensions_bytes))?;
                let leader_input_share = A::InputShare::get_decoded_with_param(
                    &(vdaf, Role::Leader.index().unwrap()),
                    &leader_input_share_bytes,
                )?;
                let helper_encrypted_input_share =
                    HpkeCiphertext::get_decoded(&helper_encrypted_input_share_bytes)?;

                ReportAggregationState::LeaderInit {
                    public_extensions,
                    public_share,
                    leader_private_extensions,
                    leader_input_share,
                    helper_encrypted_input_share,
                }
            }

            ReportAggregationStateCode::InitProcessing => {
                let verify_init_bytes =
                    self.get::<_, Option<Vec<u8>>>("verify_init")
                        .ok_or_else(|| {
                            Error::DbState(
                            "report aggregation in state INIT_PROCESSING but verify_init is NULL"
                                .to_string(),
                        )
                        })?;
                let require_taskbind_extension = self.get::<_, Option<bool>>("require_taskbind_extension")
                        .ok_or_else(|| {
                            Error::DbState(
                                "report aggregation in state INIT_PROCESSING but require_taskbind_extension is NULL"
                                    .to_string(),
                            )
                        })?;

                let verify_init = VerifyInit::get_decoded(&verify_init_bytes)?;

                ReportAggregationState::HelperInitProcessing {
                    verify_init,
                    require_taskbind_extension,
                }
            }

            ReportAggregationStateCode::Continue => {
                match role {
                    Role::Leader => {
                        let leader_verify_transition_bytes = self
                            .get::<_, Option<Vec<u8>>>("leader_verify_transition")
                            .ok_or_else(|| {
                                Error::DbState(
                                    "report aggregation in state CONTINUE but leader_verify_transition is NULL"
                                        .to_string(),
                                )
                            })?;
                        let ping_pong_transition = PingPongContinuation::get_decoded_with_param(
                            &(vdaf, 0 /* leader */),
                            &leader_verify_transition_bytes,
                        )?;

                        ReportAggregationState::LeaderContinue {
                            continuation: ping_pong_transition,
                        }
                    }
                    Role::Helper => {
                        let helper_verify_state_bytes = self
                            .get::<_, Option<Vec<u8>>>("helper_verify_state")
                            .ok_or_else(|| {
                                Error::DbState(
                                    "report aggregation in state CONTINUE but helper_verify_state is NULL"
                                        .to_string(),
                                )
                            })?;
                        let verify_state = A::VerifyState::get_decoded_with_param(
                            &(vdaf, 1 /* helper */),
                            &helper_verify_state_bytes,
                        )?;

                        ReportAggregationState::HelperContinue { verify_state }
                    }
                    _ => panic!("unexpected role"),
                }
            }

            ReportAggregationStateCode::ContinueProcessing => {
                let helper_verify_state_bytes = self
                    .get::<_, Option<Vec<u8>>>("helper_verify_state")
                    .ok_or_else(|| {
                        Error::DbState(
                            "report aggregation in state CONTINUE_PROCESSING but helper_verify_state is NULL"
                                .to_string(),
                        )
                    })?;
                let verify_continue_bytes = self
                    .get::<_, Option<Vec<u8>>>("verify_continue")
                    .ok_or_else(|| {
                        Error::DbState(
                            "report aggregation in state CONTINUE_PROCESSING but message is NULL"
                                .to_string(),
                        )
                    })?;

                let verify_state = A::VerifyState::get_decoded_with_param(
                    &(vdaf, 1 /* helper */),
                    &helper_verify_state_bytes,
                )?;
                let verify_continue = VerifyContinue::get_decoded(&verify_continue_bytes)?;

                ReportAggregationState::HelperContinueProcessing {
                    verify_state,
                    verify_continue,
                }
            }

            ReportAggregationStateCode::PollInit => {
                self.get::<_, Option<Vec<u8>>>("leader_verify_state")
                    .ok_or_else(|| {
                        Error::DbState(
                            "report aggregation in state POLL_INIT but leader_verify_state is NULL"
                                .to_string(),
                        )
                    })
                    .and_then(|encoded| {
                        Ok(ReportAggregationState::LeaderPollInit {
                            verify_state: A::VerifyState::get_decoded_with_param(
                                &(vdaf, 0 /* leader */),
                                &encoded,
                            )?,
                        })
                    })?
            }

            ReportAggregationStateCode::PollContinue => {
                self.get::<_, Option<Vec<u8>>>("leader_verify_transition")
                    .ok_or_else(|| {
                        Error::DbState(
                            "report aggregation in state POLL_CONTINUE but leader_verify_transition is NULL"
                                .to_string(),
                        )
                    })
                    .and_then(|encoded| {
                        Ok(ReportAggregationState::LeaderPollContinue {
                            continuation: PingPongContinuation::get_decoded_with_param(
                                &(vdaf, 0 /* leader */),
                                &encoded,
                            )?,
                        })
                    })?
            }

            ReportAggregationStateCode::Finished => ReportAggregationState::Finished,

            ReportAggregationStateCode::Failed => {
                let report_error = match error_code {
                    Some(c) => {
                        let c: u8 = c.try_into().map_err(|err| {
                            Error::DbState(format!("couldn't convert error_code value: {err}"))
                        })?;
                        Some(c.try_into().map_err(|err| {
                            Error::DbState(format!("couldn't convert error_code value: {err}"))
                        })?)
                    }
                    None => None,
                }
                .ok_or_else(|| {
                    Error::DbState(
                        "report aggregation in state FAILED but error_code is NULL".to_string(),
                    )
                })?;

                ReportAggregationState::Failed { report_error }
            }
        };

        Ok(ReportAggregation::new(
            *task_id,
            *aggregation_job_id,
            *report_id,
            time,
            ord,
            last_verify_resp,
            agg_state,
        ))
    }

    fn collection_job<const SEED_SIZE: usize, B, A>(
        &self,
        vdaf: &A,
        task_id: TaskId,
        batch_identifier: B::BatchIdentifier,
        collection_job_id: CollectionJobId,
    ) -> Result<CollectionJob<SEED_SIZE, B, A>, Error>
    where
        B: BatchMode,
        A: AsyncAggregator<SEED_SIZE>,
    {
        let query = Query::get_decoded(self.get("query"))?;
        let aggregation_param = A::AggregationParam::get_decoded(self.get("aggregation_param"))?;
        let state: CollectionJobStateCode = self.get("state");
        let report_count: Option<i64> = self.get("report_count");
        let client_timestamp_interval: Option<SqlInterval> = self.get("client_timestamp_interval");
        let helper_aggregate_share_bytes: Option<Vec<u8>> = self.get("helper_aggregate_share");
        let leader_aggregate_share_bytes: Option<Vec<u8>> = self.get("leader_aggregate_share");
        let aggregate_share_id = AggregateShareId::get_decoded(self.get("aggregate_share_id"))?;

        let state = match state {
            CollectionJobStateCode::Start => CollectionJobState::Start,

            CollectionJobStateCode::Poll => CollectionJobState::Poll,

            CollectionJobStateCode::Finished => {
                let report_count = u64::try_from(report_count.ok_or_else(|| {
                    Error::DbState(
                        "collection job in state FINISHED but report_count is NULL".to_string(),
                    )
                })?)?;
                let client_timestamp_interval = client_timestamp_interval
                    .ok_or_else(|| Error::DbState(
                        "collection job in state FINISHED but client_timestamp_interval is NULL".to_string())
                    )?
                    .into();
                let encrypted_helper_aggregate_share = HpkeCiphertext::get_decoded(
                    &helper_aggregate_share_bytes.ok_or_else(|| {
                        Error::DbState(
                            "collection job in state FINISHED but helper_aggregate_share is NULL"
                                .to_string(),
                        )
                    })?,
                )?;
                let leader_aggregate_share = A::AggregateShare::get_decoded_with_param(
                    &(vdaf, &aggregation_param),
                    &leader_aggregate_share_bytes.ok_or_else(|| {
                        Error::DbState(
                            "collection job is in state FINISHED but leader_aggregate_share is \
                             NULL"
                                .to_string(),
                        )
                    })?,
                )?;
                CollectionJobState::Finished {
                    report_count,
                    client_timestamp_interval,
                    encrypted_helper_aggregate_share,
                    leader_aggregate_share,
                }
            }

            CollectionJobStateCode::Abandoned => CollectionJobState::Abandoned,

            CollectionJobStateCode::Deleted => CollectionJobState::Deleted,
        };

        Ok(CollectionJob::new(
            task_id,
            collection_job_id,
            aggregate_share_id,
            query,
            aggregation_param,
            batch_identifier,
            state,
        ))
    }

    fn batch_aggregation<const SEED_SIZE: usize, B, A>(
        &self,
        vdaf: &A,
        task_id: TaskId,
        batch_identifier: B::BatchIdentifier,
        aggregation_param: A::AggregationParam,
        ord: u64,
    ) -> Result<BatchAggregation<SEED_SIZE, B, A>, Error>
    where
        B: BatchMode,
        A: AsyncAggregator<SEED_SIZE>,
    {
        let parse_values_from_row = || -> Result<_, Error> {
            let aggregate_share = self
                .get::<_, Option<Vec<u8>>>("aggregate_share")
                .map(|bytes| {
                    A::AggregateShare::get_decoded_with_param(&(vdaf, &aggregation_param), &bytes)
                })
                .transpose()
                .map_err(|_| Error::DbState("aggregate_share couldn't be parsed".to_string()))?;
            let report_count = self.get_bigint_and_convert("report_count")?;
            let checksum = ReportIdChecksum::get_decoded(self.get("checksum"))?;
            let aggregation_jobs_created =
                self.get_bigint_and_convert("aggregation_jobs_created")?;
            let aggregation_jobs_terminated =
                self.get_bigint_and_convert("aggregation_jobs_terminated")?;

            Ok((
                aggregate_share,
                report_count,
                checksum,
                aggregation_jobs_created,
                aggregation_jobs_terminated,
            ))
        };

        let client_timestamp_interval = self
            .get::<_, SqlInterval>("client_timestamp_interval")
            .into();
        let state: BatchAggregationStateCode = self.get("state");
        let state = match state {
            BatchAggregationStateCode::Aggregating => {
                let (
                    aggregate_share,
                    report_count,
                    checksum,
                    aggregation_jobs_created,
                    aggregation_jobs_terminated,
                ) = parse_values_from_row()?;
                BatchAggregationState::Aggregating {
                    aggregate_share,
                    report_count,
                    checksum,
                    aggregation_jobs_created,
                    aggregation_jobs_terminated,
                }
            }
            BatchAggregationStateCode::Collected => {
                let (
                    aggregate_share,
                    report_count,
                    checksum,
                    aggregation_jobs_created,
                    aggregation_jobs_terminated,
                ) = parse_values_from_row()?;
                BatchAggregationState::Collected {
                    aggregate_share,
                    report_count,
                    checksum,
                    aggregation_jobs_created,
                    aggregation_jobs_terminated,
                }
            }
            BatchAggregationStateCode::Scrubbed => BatchAggregationState::Scrubbed,
        };

        Ok(BatchAggregation::new(
            task_id,
            batch_identifier,
            aggregation_param,
            ord,
            client_timestamp_interval,
            state,
        ))
    }

    fn aggregate_share_job<const SEED_SIZE: usize, B, A>(
        &self,
        vdaf: &A,
        task_id: &TaskId,
        batch_identifier: B::BatchIdentifier,
        aggregation_param: A::AggregationParam,
    ) -> Result<AggregateShareJob<SEED_SIZE, B, A>, Error>
    where
        B: BatchMode,
        A: AsyncAggregator<SEED_SIZE>,
    {
        let helper_aggregate_share =
            self.get_bytea_and_decode("helper_aggregate_share", &(vdaf, &aggregation_param))?;
        let aggregate_share_id = AggregateShareId::get_decoded(self.get("aggregate_share_id"))?;
        Ok(AggregateShareJob::new(
            *task_id,
            self.get("state"),
            batch_identifier,
            aggregation_param,
            helper_aggregate_share,
            aggregate_share_id,
            self.get_bigint_and_convert("report_count")?,
            ReportIdChecksum::get_decoded(self.get("checksum"))?,
            CollectionJobReq::get_decoded(self.get("collection_job_req"))?,
        ))
    }

    fn hpke_keypair(&self, crypter: &Crypter) -> Result<HpkeKeypair, Error> {
        let config = HpkeConfig::get_decoded(self.get("config"))?;
        let config_id = u8::try_from(self.get::<_, i16>("config_id"))?;

        let encrypted_private_key: Vec<u8> = self.get("private_key");
        let private_key = HpkePrivateKey::new(crypter.decrypt(
            "hpke_keys",
            &config_id.to_be_bytes(),
            "private_key",
            &encrypted_private_key,
        )?);
        Ok(HpkeKeypair::new(
            hpke::HpkeKeypair::new(config, private_key),
            self.get("state"),
            self.get("last_state_change_at"),
        ))
    }

    fn taskprov_peer_aggregator(
        &self,
        crypter: &Crypter,
        aggregator_auth_token_rows: &[Row],
        collector_auth_token_rows: &[Row],
    ) -> Result<PeerAggregator, Error> {
        let endpoint = Url::parse(self.get("endpoint"))?;
        let endpoint_bytes = endpoint.as_str().as_ref();
        let peer_role: AggregatorRole = self.get("peer_role");
        let aggregation_mode: Option<AggregationMode> = self.get("aggregation_mode");
        let report_expiry_age = self
            .get::<_, Option<i64>>("report_expiry_age")
            .map(|d| {
                TimeDelta::try_seconds(d)
                    .ok_or_else(|| Error::TimeOverflow("report expiry age too big for timedelta"))
            })
            .transpose()?;
        let collector_hpke_config = HpkeConfig::get_decoded(self.get("collector_hpke_config"))?;

        let encrypted_verify_key_init: Vec<u8> = self.get("verify_key_init");
        let verify_key_init = crypter
            .decrypt(
                "taskprov_peer_aggregator",
                endpoint_bytes,
                "verify_key_init",
                &encrypted_verify_key_init,
            )?
            .as_slice()
            .try_into()?;

        let decrypt_tokens = |rows: &[Row], table| -> Result<Vec<_>, Error> {
            rows.iter()
                .map(|row| {
                    let ord: i64 = row.get("ord");
                    let auth_token_type: AuthenticationTokenType = row.get("type");
                    let encrypted_token: Vec<u8> = row.get("token");

                    let mut row_id = Vec::new();
                    row_id.extend_from_slice(endpoint_bytes);
                    row_id.extend_from_slice(&peer_role.as_role().get_encoded()?);
                    row_id.extend_from_slice(&ord.to_be_bytes());

                    auth_token_type.as_authentication(&crypter.decrypt(
                        table,
                        &row_id,
                        "token",
                        &encrypted_token,
                    )?)
                })
                .collect()
        };

        let aggregator_auth_tokens = decrypt_tokens(
            aggregator_auth_token_rows,
            "taskprov_aggregator_auth_tokens",
        )?;
        let collector_auth_tokens =
            decrypt_tokens(collector_auth_token_rows, "taskprov_collector_auth_tokens")?;

        PeerAggregator::new(
            endpoint,
            peer_role.as_role(),
            aggregation_mode,
            verify_key_init,
            collector_hpke_config,
            report_expiry_age,
            aggregator_auth_tokens,
            collector_auth_tokens,
        )
        .map_err(|e| Error::User(e.into()))
    }
}
