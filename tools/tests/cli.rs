use cfg_if::cfg_if;
use trycmd::TestCases;

#[test]
fn cli_tests() {
    let test_cases = TestCases::new();

    test_cases.case("tests/cmd/dap_decode.trycmd");

    cfg_if! {
        if #[cfg(feature = "fpvec_bounded_l2")] {
            test_cases.case("tests/cmd/collect_fpvec_bounded_l2.trycmd");
        } else {
            test_cases.case("tests/cmd/collect.trycmd");
        }
    }

    test_cases.run();
}
