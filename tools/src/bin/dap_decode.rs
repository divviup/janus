use anyhow::Result;
use clap::{Parser, ValueEnum};
use janus_messages::{
    AggregateShare, AggregateShareReq, AggregationJobContinueReq, AggregationJobInitializeReq,
    AggregationJobResp, CollectionJobReq, CollectionJobResp, HpkeConfig, HpkeConfigList, Report,
    batch_mode::{LeaderSelected, TimeInterval},
};
use prio::codec::Decode;
use std::{
    fmt::Debug,
    fs::File,
    io::{Read, stdin},
};

fn main() -> Result<()> {
    let options = Options::parse();

    let decoded = decode_dap_message(&options.message_file, &options.media_type)?;
    println!("{decoded:#?}");

    Ok(())
}

/// Decode the contents of `message_file` as a DAP message with `media_type`, returning the decoded
/// object.
fn decode_dap_message(message_file: &str, media_type: &MediaType) -> Result<Box<dyn Debug>> {
    let mut reader = if message_file.eq("-") {
        Box::new(stdin()) as Box<dyn Read>
    } else {
        Box::new(File::open(message_file)?) as Box<dyn Read>
    };

    let mut message_buf = Vec::new();
    reader.read_to_end(&mut message_buf)?;

    let decoded: Box<dyn Debug> = match media_type {
        MediaType::HpkeConfig => {
            let message: HpkeConfig = HpkeConfig::get_decoded(&message_buf)?;
            Box::new(message)
        }
        MediaType::HpkeConfigList => {
            let message: HpkeConfigList = HpkeConfigList::get_decoded(&message_buf)?;
            Box::new(message)
        }
        MediaType::Report => {
            let message: Report = Report::get_decoded(&message_buf)?;
            Box::new(message)
        }
        MediaType::AggregationJobInitializeReq => {
            if let Ok(decoded) =
                AggregationJobInitializeReq::<TimeInterval>::get_decoded(&message_buf)
            {
                let message: AggregationJobInitializeReq<TimeInterval> = decoded;
                Box::new(message)
            } else {
                let message: AggregationJobInitializeReq<LeaderSelected> =
                    AggregationJobInitializeReq::<LeaderSelected>::get_decoded(&message_buf)?;
                Box::new(message)
            }
        }
        MediaType::AggregationJobContinueReq => {
            let message: AggregationJobContinueReq =
                AggregationJobContinueReq::get_decoded(&message_buf)?;
            Box::new(message)
        }
        MediaType::AggregationJobResp => {
            let message: AggregationJobResp = AggregationJobResp::get_decoded(&message_buf)?;
            Box::new(message)
        }
        MediaType::AggregateShareReq => {
            if let Ok(decoded) = AggregateShareReq::<TimeInterval>::get_decoded(&message_buf) {
                let message: AggregateShareReq<TimeInterval> = decoded;
                Box::new(message)
            } else {
                let message: AggregateShareReq<LeaderSelected> =
                    AggregateShareReq::<LeaderSelected>::get_decoded(&message_buf)?;
                Box::new(message)
            }
        }
        MediaType::AggregateShare => {
            let message: AggregateShare = AggregateShare::get_decoded(&message_buf)?;
            Box::new(message)
        }
        MediaType::CollectionJobReq => {
            if let Ok(decoded) = CollectionJobReq::<TimeInterval>::get_decoded(&message_buf) {
                let message: CollectionJobReq<TimeInterval> = decoded;
                Box::new(message)
            } else {
                let message: CollectionJobReq<LeaderSelected> =
                    CollectionJobReq::<LeaderSelected>::get_decoded(&message_buf)?;
                Box::new(message)
            }
        }
        MediaType::CollectionJobResp => {
            if let Ok(decoded) = CollectionJobResp::<TimeInterval>::get_decoded(&message_buf) {
                let message: CollectionJobResp<TimeInterval> = decoded;
                Box::new(message)
            } else {
                let message: CollectionJobResp<LeaderSelected> =
                    CollectionJobResp::<LeaderSelected>::get_decoded(&message_buf)?;
                Box::new(message)
            }
        }
    };

    Ok(decoded)
}

#[derive(Debug, Clone, ValueEnum)]
#[value()]
enum MediaType {
    #[value(name = "hpke-config")]
    HpkeConfig,
    #[value(name = "hpke-config-list")]
    HpkeConfigList,
    #[value(name = "report")]
    Report,
    #[value(name = "aggregation-job-init-req")]
    AggregationJobInitializeReq,
    #[value(name = "aggregation-job-resp")]
    AggregationJobResp,
    #[value(name = "aggregation-job-continue-req")]
    AggregationJobContinueReq,
    #[value(name = "aggregate-share-req")]
    AggregateShareReq,
    #[value(name = "aggregate-share")]
    AggregateShare,
    #[value(name = "collect-job-req")]
    CollectionJobReq,
    #[value(name = "collection-job-resp")]
    CollectionJobResp,
}

#[derive(Debug, Parser)]
#[command(
    name = "dap_decode",
    about = "Distributed Aggregation Protocol message decoder",
    version,
    rename_all = "kebab-case"
)]
struct Options {
    /// Path to file containing message to decode.
    ///
    /// Pass "-" to read from stdin.
    message_file: String,

    /// Media type of the message to decode
    #[arg(long, short = 't', required = true)]
    media_type: MediaType,
}

#[cfg(test)]
mod tests {
    use crate::Options;
    use clap::CommandFactory;

    #[test]
    fn verify_clap_app() {
        Options::command().debug_assert();
    }
}
