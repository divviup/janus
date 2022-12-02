use anyhow::Result;
use clap::{Parser, ValueEnum};
use janus_messages::{
    query_type::{FixedSize, TimeInterval},
    AggregateContinueReq, AggregateContinueResp, AggregateInitializeReq, AggregateInitializeResp,
    AggregateShareReq, AggregateShareResp, CollectReq, CollectResp, HpkeConfig, Report,
};
use prio::codec::Decode;
use std::{
    fmt::Debug,
    fs::File,
    io::{stdin, Read},
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

    let decoded = match media_type {
        MediaType::HpkeConfig => Box::new(HpkeConfig::get_decoded(&message_buf)?) as Box<dyn Debug>,
        MediaType::Report => Box::new(Report::get_decoded(&message_buf)?) as Box<dyn Debug>,
        MediaType::AggregateInitializeReq => {
            if let Ok(decoded) = AggregateInitializeReq::<TimeInterval>::get_decoded(&message_buf) {
                Box::new(decoded) as Box<dyn Debug>
            } else {
                Box::new(AggregateInitializeReq::<FixedSize>::get_decoded(
                    &message_buf,
                )?) as Box<dyn Debug>
            }
        }
        MediaType::AggregateInitializeResp => {
            Box::new(AggregateInitializeResp::get_decoded(&message_buf)?) as Box<dyn Debug>
        }
        MediaType::AggregateContinueReq => {
            Box::new(AggregateContinueReq::get_decoded(&message_buf)?) as Box<dyn Debug>
        }
        MediaType::AggregateContinueResp => {
            Box::new(AggregateContinueResp::get_decoded(&message_buf)?) as Box<dyn Debug>
        }
        MediaType::AggregateShareReq => {
            if let Ok(decoded) = AggregateShareReq::<TimeInterval>::get_decoded(&message_buf) {
                Box::new(decoded) as Box<dyn Debug>
            } else {
                Box::new(AggregateShareReq::<FixedSize>::get_decoded(&message_buf))
                    as Box<dyn Debug>
            }
        }
        MediaType::AggregateShareResp => {
            Box::new(AggregateShareResp::get_decoded(&message_buf)?) as Box<dyn Debug>
        }
        MediaType::CollectReq => {
            if let Ok(decoded) = CollectReq::<TimeInterval>::get_decoded(&message_buf) {
                Box::new(decoded) as Box<dyn Debug>
            } else {
                Box::new(CollectReq::<FixedSize>::get_decoded(&message_buf)?) as Box<dyn Debug>
            }
        }
        MediaType::CollectResp => {
            if let Ok(decoded) = CollectResp::<TimeInterval>::get_decoded(&message_buf) {
                Box::new(decoded) as Box<dyn Debug>
            } else {
                Box::new(CollectResp::<FixedSize>::get_decoded(&message_buf)?) as Box<dyn Debug>
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
    #[value(name = "report")]
    Report,
    #[value(name = "aggregate-initialize-req")]
    AggregateInitializeReq,
    #[value(name = "aggregate-initialize-resp")]
    AggregateInitializeResp,
    #[value(name = "aggregate-continue-req")]
    AggregateContinueReq,
    #[value(name = "aggregate-continue-resp")]
    AggregateContinueResp,
    #[value(name = "aggregate-share-req")]
    AggregateShareReq,
    #[value(name = "aggregate-share-resp")]
    AggregateShareResp,
    #[value(name = "collect-req")]
    CollectReq,
    #[value(name = "collect-resp")]
    CollectResp,
}

#[derive(Debug, Parser)]
#[command(
    name = "dap-decode",
    about = "Distributed Aggregation Protocol message decoder",
    version,
    rename_all = "kebab-case"
)]
struct Options {
    /// Path to file containing message to decode. Pass "-" to read from stdin.
    message_file: String,

    /// Media type of the message to decode.
    #[arg(long, short = 't', required = true)]
    media_type: MediaType,
}
