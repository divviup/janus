//! Common functionality for PPM aggregators
use crate::{
    hpke::{HpkeRecipient, Label},
    message::{Role, TaskId},
};
use http::{header::CACHE_CONTROL, StatusCode};
use prio::codec::Encode;
use std::{future::Future, net::SocketAddr};
use warp::{filters::BoxedFilter, reply, trace, Filter, Reply};

/// Constructs a Warp filter with an aggregator's endpoints.
fn aggregator_filter(task_id: TaskId) -> BoxedFilter<(impl Reply,)> {
    let hpke_recipient =
        HpkeRecipient::generate(task_id, Label::InputShare, Role::Client, Role::Leader);

    let hpke_config_encoded = hpke_recipient.config.get_encoded();

    warp::path("hpke_config")
        .and(warp::get())
        .map(move || {
            reply::with_header(
                reply::with_status(hpke_config_encoded.clone(), StatusCode::OK),
                CACHE_CONTROL,
                "max-age=86400",
            )
        })
        .with(trace::named("hpke_config"))
        .boxed()
}

/// Construct a PPM aggregator server, listening on the provided [`SocketAddr`].
/// If the `SocketAddr`'s `port` is 0, an ephemeral port is used. Returns a
/// `SocketAddr` representing the address and port the server are listening on
/// and a future that can be `await`ed to begin serving requests.
pub fn aggregator_server(
    task_id: TaskId,
    listen_address: SocketAddr,
) -> (SocketAddr, impl Future<Output = ()> + 'static) {
    let routes = aggregator_filter(task_id).with(trace::request());

    warp::serve(routes).bind_ephemeral(listen_address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::HpkeConfig;
    use hyper::body::to_bytes;
    use prio::codec::Decode;
    use std::io::Cursor;
    use warp::reply::Reply;

    #[tokio::test]
    async fn hpke_config() {
        let task_id = TaskId::random();

        let response = warp::test::request()
            .path("/hpke_config")
            .filter(&aggregator_filter(task_id))
            .await
            .unwrap()
            .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CACHE_CONTROL).unwrap(),
            "max-age=86400"
        );

        let body = response.into_body();
        let bytes = to_bytes(body).await.unwrap();
        let _hpke_config = HpkeConfig::decode(&mut Cursor::new(&bytes)).unwrap();
        // TODO: encrypt a message to the HPKE config
    }
}
