#![no_main]
#![no_std]

use riot_rs as _;

#[cfg(not(feature = "riot-wrappers"))]
use riot_rs::rt::debug::println;

#[cfg(feature = "riot-wrappers")]
use riot_wrappers::println;

use riot_rs::rt::debug::exit;

use edhoc_crypto;
use edhoc_rs::*;
use hexlit::hex;

const CRED_I: &[u8] = &hex!("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8"
);
const I: &[u8] = &hex!("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
const R: &[u8] = &hex!("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac");
const CRED_R: &[u8] = &hex!("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");

#[no_mangle]
fn riot_main() {
    println!(
        "Hello from riot_main()! Running on a {} board.",
        riot_rs::buildinfo::BOARD
    );

    fn test_handshake() {
        let state_initiator = Default::default();
        let initiator = EdhocInitiator::new(
            state_initiator,
            edhoc_crypto::default_crypto(),
            I,
            CRED_I,
            Some(CRED_R),
        );
        let state_responder = Default::default();
        let responder = EdhocResponder::new(
            state_responder,
            edhoc_crypto::default_crypto(),
            R,
            CRED_R,
            Some(CRED_I),
        );

        let c_i: u8 =
            generate_connection_identifier_cbor(&mut edhoc_crypto::default_crypto()).into();
        let (initiator, message_1) = initiator.prepare_message_1(c_i).unwrap(); // to update the state

        let responder = responder.process_message_1(&message_1).unwrap();

        let c_r: u8 =
            generate_connection_identifier_cbor(&mut edhoc_crypto::default_crypto()).into();
        let (responder, message_2) = responder.prepare_message_2(c_r).unwrap();
        assert!(c_r != 0xff);

        let (initiator, _c_r) = initiator.process_message_2(&message_2).unwrap();

        let (mut initiator, message_3, i_prk_out) = initiator.prepare_message_3().unwrap();

        let (mut responder, r_prk_out) = responder.process_message_3(&message_3).unwrap();

        // check that prk_out is equal at initiator and responder side
        assert_eq!(i_prk_out, r_prk_out);

        // derive OSCORE secret and salt at both sides and compare
        let i_oscore_secret = initiator.edhoc_exporter(0u8, &[], 16); // label is 0
        let i_oscore_salt = initiator.edhoc_exporter(1u8, &[], 8); // label is 1

        let r_oscore_secret = responder.edhoc_exporter(0u8, &[], 16); // label is 0
        let r_oscore_salt = responder.edhoc_exporter(1u8, &[], 8); // label is 1

        assert_eq!(i_oscore_secret, r_oscore_secret);
        assert_eq!(i_oscore_salt, r_oscore_salt);
    }

    test_handshake();
    println!("Test test_handshake passed.");
    println!("All tests passed.");

    exit(Ok(()));
}
