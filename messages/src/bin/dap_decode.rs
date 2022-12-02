use anyhow::Result;
use clap::{Parser, ValueEnum};
use janus_messages::{
    query_type::TimeInterval, AggregateContinueReq, AggregateContinueResp, AggregateInitializeReq,
    AggregateInitializeResp, AggregateShareReq, AggregateShareResp, CollectReq, CollectResp,
    HpkeConfig, Report,
};
use prio::codec::Decode;
use std::{
    fmt::Debug,
    fs::File,
    io::{stdin, Cursor, Read},
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

    let mut binary_message = Cursor::new(message_buf.as_slice());

    let decoded = match media_type {
        MediaType::HpkeConfig => {
            Box::new(HpkeConfig::decode(&mut binary_message)?) as Box<dyn Debug>
        }
        MediaType::Report => Box::new(Report::decode(&mut binary_message)?) as Box<dyn Debug>,
        MediaType::AggregateInitializeReq => Box::new(
            AggregateInitializeReq::<TimeInterval>::decode(&mut binary_message)?,
        ) as Box<dyn Debug>,
        MediaType::AggregateInitializeResp => {
            Box::new(AggregateInitializeResp::decode(&mut binary_message)?) as Box<dyn Debug>
        }
        MediaType::AggregateContinueReq => {
            Box::new(AggregateContinueReq::decode(&mut binary_message)?) as Box<dyn Debug>
        }
        MediaType::AggregateContinueResp => {
            Box::new(AggregateContinueResp::decode(&mut binary_message)?) as Box<dyn Debug>
        }
        MediaType::AggregateShareReq => Box::new(AggregateShareReq::<TimeInterval>::decode(
            &mut binary_message,
        )?) as Box<dyn Debug>,
        MediaType::AggregateShareResp => {
            Box::new(AggregateShareResp::decode(&mut binary_message)?) as Box<dyn Debug>
        }
        MediaType::CollectReq => {
            Box::new(CollectReq::<TimeInterval>::decode(&mut binary_message)?) as Box<dyn Debug>
        }
        MediaType::CollectResp => {
            Box::new(CollectResp::<TimeInterval>::decode(&mut binary_message)?) as Box<dyn Debug>
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
