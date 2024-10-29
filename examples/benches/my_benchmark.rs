
use std::collections::HashMap;
use std::mem;
use std::ops::Add;
use std::process::exit;
use std::time::Duration;

use identity_eddsa_verifier::Ed25519Verifier;
use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::core::Duration as Dur;

use criterion::black_box;
use criterion::criterion_group;
use criterion::criterion_main;
use criterion::Criterion;
use examples::*;
use examples::MemStorage;

use identity_iota::core::FromJson;
use identity_iota::core::Object;
use identity_iota::core::Timestamp;
use identity_iota::core::ToJson;
use identity_iota::core::Url;
use identity_iota::credential::Credential;
use identity_iota::credential::CredentialBuilder;
use identity_iota::credential::DecodedJptCredential;
use identity_iota::credential::DecodedJwtCredential;
use identity_iota::credential::DecodedJwtPresentation;
use identity_iota::credential::FailFast;
use identity_iota::credential::Jpt;
use identity_iota::credential::JptCredentialValidationOptions;
use identity_iota::credential::JptCredentialValidator;
use identity_iota::credential::JptPresentationValidationOptions;
use identity_iota::credential::JptPresentationValidator;
use identity_iota::credential::JwpCredentialOptions;
use identity_iota::credential::JwpPresentationOptions;
use identity_iota::credential::Jwt;
use identity_iota::credential::JwtCredentialValidationOptions;
use identity_iota::credential::JwtCredentialValidator;
use identity_iota::credential::JwtCredentialValidatorUtils;
use identity_iota::credential::JwtPresentationOptions;
use identity_iota::credential::JwtPresentationValidationOptions;
use identity_iota::credential::JwtPresentationValidator;
use identity_iota::credential::JwtPresentationValidatorUtils;
use identity_iota::credential::Presentation;
use identity_iota::credential::PresentationBuilder;
use identity_iota::credential::SelectiveDisclosurePresentation;
use identity_iota::credential::Subject;
use identity_iota::credential::SubjectHolderRelationship;
use identity_iota::did::CoreDID;
use identity_iota::did::DID;
use identity_iota::document;
use identity_iota::document::verifiable::JwsVerificationOptions;
use identity_iota::document::CoreDocument;
use identity_iota::iota::IotaClientExt;
use identity_iota::iota::IotaDocument;
use identity_iota::iota::IotaIdentityClientExt;
use identity_iota::iota::NetworkName;
use identity_iota::resolver::Resolver;
use identity_iota::storage::JwkDocumentExt;
use identity_iota::storage::JwkMemStore;
use identity_iota::storage::JwkStorage;
use identity_iota::storage::JwpDocumentExt;
use identity_iota::storage::JwsSignatureOptions;
use identity_iota::storage::KeyIdMemstore;
use identity_iota::storage::KeyType;
use identity_iota::storage::Storage;
use identity_iota::verification::jws::JwsAlgorithm;
use identity_iota::verification::MethodScope;
use iota_sdk::client::secret::stronghold::StrongholdSecretManager;
use iota_sdk::client::secret::SecretManager;
use iota_sdk::client::Client;
use iota_sdk::client::Password;
use iota_sdk::types::block::address::Address;
use iota_sdk::types::block::output::AliasOutput;
use jsonprooftoken::jpa::algs::ProofAlgorithm;
use rand::rngs::mock;
use serde_json::json;
use tokio::runtime::Runtime;
use tokio::task;
use tokio::time::Instant;
use tokio::try_join;

use criterion::*;
use criterion::async_executor::AsyncExecutor;
use zkryptium::keys::pair::KeyPair;
use zkryptium::schemes::algorithms::BbsBls12381Sha256;
use zkryptium::schemes::algorithms::BbsBls12381Shake256;
use zkryptium::schemes::generics::Signature;

// The API endpoint of an IOTA node, e.g. Hornet.
// const API_ENDPOINT: &str = "http://192.168.94.191";
const API_ENDPOINT: &str = "http://api.testnet.shimmer.network";
// The faucet endpoint allows requesting funds for testing purposes.
const FAUCET_ENDPOINT: &str = "http://faucet.testnet.shimmer.network/api/enqueue";

// // The API endpoint of an IOTA node, e.g. Hornet.
// const API_ENDPOINT: &str = "http://localhost";
// // The faucet endpoint allows requesting funds for testing purposes.
// const FAUCET_ENDPOINT: &str = "http://localhost/faucet/api/enqueue";


async fn create_did(client: &Client, address: Address, network_name: &NetworkName, secret_manager: &SecretManager, storage: &MemStorage, key_type: KeyType, alg: Option<JwsAlgorithm>, proof_alg: Option<ProofAlgorithm>) -> (Address, IotaDocument, String) {

  // Create a new DID document with a placeholder DID.
  // The DID will be derived from the Alias Id of the Alias Output after publishing.
  let mut document: IotaDocument = IotaDocument::new(network_name);

  // New Verification Method containing a Ed25519 key


  let fragment = if let Some(algorithm) = alg  {
  
    document.generate_method(
        &storage, 
        key_type, 
        algorithm, 
        None, 
        MethodScope::VerificationMethod
    ).await.unwrap()

  } else if let Some(algorithm) = proof_alg {

    document.generate_method_jwp(
        &storage, 
        key_type, 
        algorithm, 
        None, 
        MethodScope::VerificationMethod
    ).await.unwrap()

  } else {
    panic!("SHOULD NOT HAPPEN");
  };


  // Construct an Alias Output containing the DID document, with the wallet address
  // set as both the state controller and governor.
  let alias_output: AliasOutput = client.new_did_output(address, document.clone(), None).await.unwrap();

  // Publish the Alias Output and get the published DID document.
  let document: IotaDocument = client.publish_did_output(&secret_manager, alias_output).await.unwrap();

  (address, document, fragment)
}


async fn create_presented_jwp(challenge: &str, decoded_jpt: &DecodedJptCredential, document: &CoreDocument, attributes_undisclosed: usize) -> Jpt {

    // =========================================================================================================
    // Step 6: Holder engages in the Selective Disclosure of credential's attributes.
    // =========================================================================================================

    let method_id = decoded_jpt
        .decoded_jwp
        .get_issuer_protected_header()
        .kid()
        .unwrap();

    let mut selective_disclosure_presentation = SelectiveDisclosurePresentation::new(&decoded_jpt.decoded_jwp);

    match attributes_undisclosed {
        0 => {},
        1 => selective_disclosure_presentation.conceal_in_subject("vc.credentialSubject.A0").unwrap(),
        2 => {
            selective_disclosure_presentation.conceal_in_subject("vc.credentialSubject.A0").unwrap();
            selective_disclosure_presentation.conceal_in_subject("vc.credentialSubject.A1").unwrap();
        },
        3 => {
            selective_disclosure_presentation.conceal_in_subject("vc.credentialSubject.A0").unwrap();
            selective_disclosure_presentation.conceal_in_subject("vc.credentialSubject.A1").unwrap();
            selective_disclosure_presentation.conceal_in_subject("vc.credentialSubject.A2").unwrap();
        },
        4 => {
            selective_disclosure_presentation.conceal_in_subject("vc.credentialSubject.A0").unwrap();
            selective_disclosure_presentation.conceal_in_subject("vc.credentialSubject.A1").unwrap();
            selective_disclosure_presentation.conceal_in_subject("vc.credentialSubject.A2").unwrap();
            selective_disclosure_presentation.conceal_in_subject("vc.credentialSubject.A3").unwrap();
        },
        5 => {
            selective_disclosure_presentation.conceal_in_subject("vc.credentialSubject.A0").unwrap();
            selective_disclosure_presentation.conceal_in_subject("vc.credentialSubject.A1").unwrap();
            selective_disclosure_presentation.conceal_in_subject("vc.credentialSubject.A2").unwrap();
            selective_disclosure_presentation.conceal_in_subject("vc.credentialSubject.A3").unwrap();
            selective_disclosure_presentation.conceal_in_subject("vc.credentialSubject.A4").unwrap();
        },
        _ => panic!("SHOULD NOT HAPPEN")
    }
    


    // =======================================================================================================================================
    // Step 7: Holder needs Issuer's Public Key to compute the Signature Proof of Knowledge and construct the Presentation
    // JPT.
    // =======================================================================================================================================

    // Construct a JPT(JWP in the Presentation form) representing the Selectively Disclosed Verifiable Credential
    let presentation_jpt: Jpt = document
        .create_presentation_jpt(
        &mut selective_disclosure_presentation,
        method_id,
        &JwpPresentationOptions::default().nonce(challenge),
        )
        .await.unwrap();

    presentation_jpt
}



async fn setup(key_type: KeyType, proof_alg: ProofAlgorithm, n_attr: usize) -> (CoreDocument, MemStorage, String, Credential) {
    
    let client: Client = Client::builder()
    .with_primary_node(API_ENDPOINT, None).unwrap()
    .finish()
    .await.unwrap();
  
    
    // Get the Bech32 human-readable part (HRP) of the network.
    let network_name: NetworkName = client.network_name().await.unwrap();
  
    // Create a new DID document with a placeholder DID.
    // The DID will be derived from the Alias Id of the Alias Output after publishing.
    let mut document: IotaDocument = IotaDocument::new(&network_name);
  
    let storage = Storage::new(JwkMemStore::new(), KeyIdMemstore::new());
  
  
    let fragment = 
        document.generate_method_jwp(
            &storage, 
            key_type, 
            proof_alg, 
            None, 
            MethodScope::VerificationMethod
        ).await.unwrap();

        let attribute0: String = std::iter::repeat('0').take(98).collect(); // +2 for ""
        let attribute1: String = std::iter::repeat('1').take(98).collect(); // +2 for ""
        let attribute2: String = std::iter::repeat('2').take(98).collect(); // +2 for ""
        let attribute3: String = std::iter::repeat('3').take(98).collect(); // +2 for ""
        let attribute4: String = std::iter::repeat('4').take(98).collect(); // +2 for ""

        let v0 = json!({
            "A0": attribute0,
            // "A1": attribute1,
            // "A2": attribute2
          });

          let v1 = json!({
            "A0": attribute0,
            "A1": attribute1,
            // "A2": attribute2
          });

          let v2 = json!({
            "A0": attribute0,
            "A1": attribute1,
            "A2": attribute2
          });

          let v3 = json!({
            "A0": attribute0,
            "A1": attribute1,
            "A2": attribute2,
            "A3": attribute3
          });

          let v4 = json!({
            "A0": attribute0,
            "A1": attribute1,
            "A2": attribute2,
            "A3": attribute3,
            "A4": attribute4
          });


             // Create a credential subject indicating the degree earned by Alice.
             let subject: Subject = match n_attr {
                 1 =>  Subject::from_json_value(v0).unwrap(),
                 2 => Subject::from_json_value(v1).unwrap(),
                 3 => Subject::from_json_value(v2).unwrap(),
                 4 => Subject::from_json_value(v3).unwrap(),
                 5 => Subject::from_json_value(v4).unwrap(),
                 _ => panic!("wrong number of attributes (1,2,3,4,5)")
             };


  // Build credential using subject above and issuer.
  let credential: Credential = CredentialBuilder::default()
    .id(Url::parse("https://example.edu/credentials/3732").unwrap())
    .issuer(Url::parse(document.id().as_str()).unwrap())
    .type_("UniversityDegreeCredential")
    .subject(subject)
    .build().unwrap();
  
    (document.into(), storage, fragment, credential)
  }


fn benchmark_issued_jwp_gen(c: &mut Criterion) {

    let tokio = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("Issued JWP");
    group.sample_size(1000);
    group.warm_up_time(Duration::from_secs(20));


    /* A0 */

    let (document, storage, kid, credential) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup(JwkMemStore::BLS12381G2_KEY_TYPE, ProofAlgorithm::BLS12381_SHA256, 1).await });

    println!("VC: {}", credential.to_json_vec().unwrap().len());

    group.bench_function("BLS12-381-SHA-256 - (A0)", |b| b.to_async(&tokio).iter(|| async {
        document
            .create_credential_jpt(
            &credential,
            &storage,
            &kid,
            &JwpCredentialOptions::default(),
            None,
            )
            .await.unwrap();
        }
        
    ));


    let jpt = tokio::runtime::Runtime::new().unwrap().block_on(async {
        document
        .create_credential_jpt(
        &credential,
        &storage,
        &kid,
        &JwpCredentialOptions::default(),
        None,
        )
        .await.unwrap()
    });
    println!("BLS12-381-SHA-256 - VC (JPT) size = {}", jpt.as_str().as_bytes().len());



    let (document, storage, kid, credential) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup(JwkMemStore::BLS12381G2_KEY_TYPE, ProofAlgorithm::BLS12381_SHAKE256, 1 ).await });


    group.bench_function("BLS12-381-SHAKE-256 - (A0)", |b| b.to_async(&tokio).iter(|| async {
        document
            .create_credential_jpt(
            &credential,
            &storage,
            &kid,
            &JwpCredentialOptions::default(),
            None,
            )
            .await.unwrap();
        }
    ));

    let jpt = tokio::runtime::Runtime::new().unwrap().block_on(async {
        document
        .create_credential_jpt(
        &credential,
        &storage,
        &kid,
        &JwpCredentialOptions::default(),
        None,
        )
        .await.unwrap()
    });

    println!("BLS12-381-SHAKE-256 - VC (JPT) size = {}", jpt.as_str().as_bytes().len());

    /* A0 + A1 */

    let (document, storage, kid, credential) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup(JwkMemStore::BLS12381G2_KEY_TYPE, ProofAlgorithm::BLS12381_SHA256, 2).await });

    println!("VC: {}", credential.to_json_vec().unwrap().len());

    group.bench_function("BLS12-381-SHA-256 - (A0 + A1)", |b| b.to_async(&tokio).iter(|| async {
        document
            .create_credential_jpt(
            &credential,
            &storage,
            &kid,
            &JwpCredentialOptions::default(),
            None,
            )
            .await.unwrap();
        }
        
    ));


    let jpt = tokio::runtime::Runtime::new().unwrap().block_on(async {
        document
        .create_credential_jpt(
        &credential,
        &storage,
        &kid,
        &JwpCredentialOptions::default(),
        None,
        )
        .await.unwrap()
    });

    println!("BLS12-381-SHA-256 - VC (JPT) size = {}", jpt.as_str().as_bytes().len());


    let (document, storage, kid, credential) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup(JwkMemStore::BLS12381G2_KEY_TYPE, ProofAlgorithm::BLS12381_SHAKE256, 2 ).await });


    group.bench_function("BLS12-381-SHAKE-256 - (A0 + A1)", |b| b.to_async(&tokio).iter(|| async {
        document
            .create_credential_jpt(
            &credential,
            &storage,
            &kid,
            &JwpCredentialOptions::default(),
            None,
            )
            .await.unwrap();
        }
    ));

    let jpt = tokio::runtime::Runtime::new().unwrap().block_on(async {
        document
        .create_credential_jpt(
        &credential,
        &storage,
        &kid,
        &JwpCredentialOptions::default(),
        None,
        )
        .await.unwrap()
    });

    println!("BLS12-381-SHAKE-256 - VC (JPT) size = {}", jpt.as_str().as_bytes().len());

    /* A0 + A1 + A2 */


    let (document, storage, kid, credential) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup(JwkMemStore::BLS12381G2_KEY_TYPE, ProofAlgorithm::BLS12381_SHA256, 3).await });

    println!("VC: {}", credential.to_json_vec().unwrap().len());

    group.bench_function("BLS12-381-SHA-256 - (A0 + A1 + A2)", |b| b.to_async(&tokio).iter(|| async {
        document
            .create_credential_jpt(
            &credential,
            &storage,
            &kid,
            &JwpCredentialOptions::default(),
            None,
            )
            .await.unwrap();
        }
        
    ));


    let jpt = tokio::runtime::Runtime::new().unwrap().block_on(async {
        document
        .create_credential_jpt(
        &credential,
        &storage,
        &kid,
        &JwpCredentialOptions::default(),
        None,
        )
        .await.unwrap()
    });

    println!("BLS12-381-SHA-256 - VC (JPT) size = {}", jpt.as_str().as_bytes().len());


    let (document, storage, kid, credential) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup(JwkMemStore::BLS12381G2_KEY_TYPE, ProofAlgorithm::BLS12381_SHAKE256, 3 ).await });


    group.bench_function("BLS12-381-SHAKE-256 - (A0 + A1 + A2)", |b| b.to_async(&tokio).iter(|| async {
        document
            .create_credential_jpt(
            &credential,
            &storage,
            &kid,
            &JwpCredentialOptions::default(),
            None,
            )
            .await.unwrap();
        }
    ));

    let jpt = tokio::runtime::Runtime::new().unwrap().block_on(async {
        document
        .create_credential_jpt(
        &credential,
        &storage,
        &kid,
        &JwpCredentialOptions::default(),
        None,
        )
        .await.unwrap()
    });

    println!("BLS12-381-SHAKE-256 - VC (JPT) size = {}", jpt.as_str().as_bytes().len());

    /* A0 + A1 + A2 * A3*/


    let (document, storage, kid, credential) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup(JwkMemStore::BLS12381G2_KEY_TYPE, ProofAlgorithm::BLS12381_SHA256, 4).await });

    println!("VC: {}", credential.to_json_vec().unwrap().len());

    group.bench_function("BLS12-381-SHA-256 - (A0 + A1 + A2 + A3)", |b| b.to_async(&tokio).iter(|| async {
        document
            .create_credential_jpt(
            &credential,
            &storage,
            &kid,
            &JwpCredentialOptions::default(),
            None,
            )
            .await.unwrap();
        }
        
    ));


    let jpt = tokio::runtime::Runtime::new().unwrap().block_on(async {
        document
        .create_credential_jpt(
        &credential,
        &storage,
        &kid,
        &JwpCredentialOptions::default(),
        None,
        )
        .await.unwrap()
    });

    println!("BLS12-381-SHA-256 - VC (JPT) size = {}", jpt.as_str().as_bytes().len());


    let (document, storage, kid, credential) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup(JwkMemStore::BLS12381G2_KEY_TYPE, ProofAlgorithm::BLS12381_SHAKE256, 4).await });


    group.bench_function("BLS12-381-SHAKE-256 - (A0 + A1 + A2 + A3)", |b| b.to_async(&tokio).iter(|| async {
        document
            .create_credential_jpt(
            &credential,
            &storage,
            &kid,
            &JwpCredentialOptions::default(),
            None,
            )
            .await.unwrap();
        }
    ));

    let jpt = tokio::runtime::Runtime::new().unwrap().block_on(async {
        document
        .create_credential_jpt(
        &credential,
        &storage,
        &kid,
        &JwpCredentialOptions::default(),
        None,
        )
        .await.unwrap()
    });

    println!("BLS12-381-SHAKE-256 - VC (JPT) size = {}", jpt.as_str().as_bytes().len());


    /* A0 + A1 + A2 + A3 + A4 */


    let (document, storage, kid, credential) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup(JwkMemStore::BLS12381G2_KEY_TYPE, ProofAlgorithm::BLS12381_SHA256, 5).await });

    println!("VC: {}", credential.to_json_vec().unwrap().len());

    group.bench_function("BLS12-381-SHA-256 - (A0 + A1 + A2 + A3 + A4)", |b| b.to_async(&tokio).iter(|| async {
        document
            .create_credential_jpt(
            &credential,
            &storage,
            &kid,
            &JwpCredentialOptions::default(),
            None,
            )
            .await.unwrap();
        }
        
    ));


    let jpt = tokio::runtime::Runtime::new().unwrap().block_on(async {
        document
        .create_credential_jpt(
        &credential,
        &storage,
        &kid,
        &JwpCredentialOptions::default(),
        None,
        )
        .await.unwrap()
    });

    println!("BLS12-381-SHA-256 - VC (JPT) size = {}", jpt.as_str().as_bytes().len());


    let (document, storage, kid, credential) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup(JwkMemStore::BLS12381G2_KEY_TYPE, ProofAlgorithm::BLS12381_SHAKE256, 5 ).await });


    group.bench_function("BLS12-381-SHAKE-256 - (A0 + A1 + A2 + A3 + A4)", |b| b.to_async(&tokio).iter(|| async {
        document
            .create_credential_jpt(
            &credential,
            &storage,
            &kid,
            &JwpCredentialOptions::default(),
            None,
            )
            .await.unwrap();
        }
    ));

    let jpt = tokio::runtime::Runtime::new().unwrap().block_on(async {
        document
        .create_credential_jpt(
        &credential,
        &storage,
        &kid,
        &JwpCredentialOptions::default(),
        None,
        )
        .await.unwrap()
    });

    println!("BLS12-381-SHAKE-256 - VC (JPT) size = {}", jpt.as_str().as_bytes().len());

}


fn benchmark_presented_jwp_gen(c: &mut Criterion) {

    let tokio = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("Presented JWP");
    group.sample_size(1000);
    group.warm_up_time(Duration::from_secs(20));



    let (document, decoded_jpt) = tokio::runtime::Runtime::new().unwrap().block_on(
        async { 

            let (document, storage, kid, credential) = setup(JwkMemStore::BLS12381G2_KEY_TYPE, ProofAlgorithm::BLS12381_SHA256, 5 ).await;
            let credential_jpt = document
            .create_credential_jpt(
            &credential,
            &storage,
            &kid,
            &JwpCredentialOptions::default(),
            None,
            )
            .await.unwrap();


            let decoded_jpt = JptCredentialValidator::validate::<_, Object>(
                &credential_jpt,
                &document,
                &JptCredentialValidationOptions::default(),
                FailFast::FirstError,
              )
              .unwrap();
        
              (document, decoded_jpt)
        });

    // A unique random challenge generated by the requester per presentation can mitigate replay attacks.
    let challenge: &str = "475a7984-1bb5-4c4c-a56f-822bccd46440";

    group.bench_function("BLS12-381-SHA-256 - (ALL attributes disclosed)", |b| b.to_async(&tokio).iter(|| async {
            create_presented_jwp(challenge, &decoded_jpt, &document, 0).await;
        }
        
    ));


    let presentation_jpt = tokio::runtime::Runtime::new().unwrap().block_on(async { create_presented_jwp(challenge, &decoded_jpt, &document, 0).await });



    group.bench_function("Decode/Verify - BLS12-381-SHA-256 - (ALL attributes disclosed)", |b| b.to_async(&tokio).iter(|| async {
        let presentation_validation_options = JptPresentationValidationOptions::default().nonce(challenge.clone());

        // Verifier validate the Presented Credential and retrieve the JwpPresented
        let decoded_presented_credential = JptPresentationValidator::validate::<_, Object>(
            &presentation_jpt,
            &document,
            &presentation_validation_options,
            FailFast::FirstError,
        )
        .unwrap();
        }
        
    ));



    // A0 undisclosed

    group.bench_function("BLS12-381-SHA-256 - (A0 undisclosed)", |b| b.to_async(&tokio).iter(|| async {
        create_presented_jwp(challenge, &decoded_jpt, &document, 1).await;
    }
    
    ));


    let presentation_jpt = tokio::runtime::Runtime::new().unwrap().block_on(async { create_presented_jwp(challenge, &decoded_jpt, &document, 0).await });



    group.bench_function("Decode/Verify - BLS12-381-SHA-256 - (A0 undisclosed)", |b| b.to_async(&tokio).iter(|| async {
        let presentation_validation_options = JptPresentationValidationOptions::default().nonce(challenge.clone());

        // Verifier validate the Presented Credential and retrieve the JwpPresented
        let decoded_presented_credential = JptPresentationValidator::validate::<_, Object>(
            &presentation_jpt,
            &document,
            &presentation_validation_options,
            FailFast::FirstError,
        )
        .unwrap();
        }
        
    ));


    // A0 + A1 undisclosed

    group.bench_function("BLS12-381-SHA-256 - (A0 + A1 undisclosed)", |b| b.to_async(&tokio).iter(|| async {
        create_presented_jwp(challenge, &decoded_jpt, &document, 2).await;
    }
    
    ));


    let presentation_jpt = tokio::runtime::Runtime::new().unwrap().block_on(async { create_presented_jwp(challenge, &decoded_jpt, &document, 0).await });



    group.bench_function("Decode/Verify - BLS12-381-SHA-256 - (A0 + A1 undisclosed)", |b| b.to_async(&tokio).iter(|| async {
        let presentation_validation_options = JptPresentationValidationOptions::default().nonce(challenge.clone());

        // Verifier validate the Presented Credential and retrieve the JwpPresented
        let decoded_presented_credential = JptPresentationValidator::validate::<_, Object>(
            &presentation_jpt,
            &document,
            &presentation_validation_options,
            FailFast::FirstError,
        )
        .unwrap();
        }
        
    ));


    // A0 + A1 + A2 undisclosed

    group.bench_function("BLS12-381-SHA-256 - (A0 + A1 + A2 undisclosed)", |b| b.to_async(&tokio).iter(|| async {
        create_presented_jwp(challenge, &decoded_jpt, &document, 3).await;
    }
    
    ));


    let presentation_jpt = tokio::runtime::Runtime::new().unwrap().block_on(async { create_presented_jwp(challenge, &decoded_jpt, &document, 0).await });



    group.bench_function("Decode/Verify - BLS12-381-SHA-256 - (A0 + A1 + A2 undisclosed)", |b| b.to_async(&tokio).iter(|| async {
        let presentation_validation_options = JptPresentationValidationOptions::default().nonce(challenge.clone());

        // Verifier validate the Presented Credential and retrieve the JwpPresented
        let decoded_presented_credential = JptPresentationValidator::validate::<_, Object>(
            &presentation_jpt,
            &document,
            &presentation_validation_options,
            FailFast::FirstError,
        )
        .unwrap();
        }
        
    ));


    // A0 + A1 + A2 + A3 undisclosed

    group.bench_function("BLS12-381-SHA-256 - (A0 + A1 + A2 + A3 undisclosed)", |b| b.to_async(&tokio).iter(|| async {
        create_presented_jwp(challenge, &decoded_jpt, &document, 4).await;
    }
    
    ));


    let presentation_jpt = tokio::runtime::Runtime::new().unwrap().block_on(async { create_presented_jwp(challenge, &decoded_jpt, &document, 0).await });



    group.bench_function("Decode/Verify - BLS12-381-SHA-256 - (A0 + A1 + A2 + A3 undisclosed)", |b| b.to_async(&tokio).iter(|| async {
        let presentation_validation_options = JptPresentationValidationOptions::default().nonce(challenge.clone());

        // Verifier validate the Presented Credential and retrieve the JwpPresented
        let decoded_presented_credential = JptPresentationValidator::validate::<_, Object>(
            &presentation_jpt,
            &document,
            &presentation_validation_options,
            FailFast::FirstError,
        )
        .unwrap();
        }
        
    ));


    // A0 + A1 + A2 + A3 + A4 undisclosed

    group.bench_function("BLS12-381-SHA-256 - (A0 + A1 + A2 + A3 + A4 undisclosed)", |b| b.to_async(&tokio).iter(|| async {
        create_presented_jwp(challenge, &decoded_jpt, &document, 5).await;
    }
    
    ));


    let presentation_jpt = tokio::runtime::Runtime::new().unwrap().block_on(async { create_presented_jwp(challenge, &decoded_jpt, &document, 0).await });


    group.bench_function("Decode/Verify - BLS12-381-SHA-256 - (A0 + A1 + A2 + A3 + A4 undisclosed)", |b| b.to_async(&tokio).iter(|| async {
        let presentation_validation_options = JptPresentationValidationOptions::default().nonce(challenge.clone());

        // Verifier validate the Presented Credential and retrieve the JwpPresented
        let decoded_presented_credential = JptPresentationValidator::validate::<_, Object>(
            &presentation_jpt,
            &document,
            &presentation_validation_options,
            FailFast::FirstError,
        )
        .unwrap();
        }
        
    ));



    // SHAKE


    let (document, decoded_jpt) = tokio::runtime::Runtime::new().unwrap().block_on(
        async { 

            let (document, storage, kid, credential) = setup(JwkMemStore::BLS12381G2_KEY_TYPE, ProofAlgorithm::BLS12381_SHAKE256, 5 ).await;
            let credential_jpt = document
            .create_credential_jpt(
            &credential,
            &storage,
            &kid,
            &JwpCredentialOptions::default(),
            None,
            )
            .await.unwrap();


            let decoded_jpt = JptCredentialValidator::validate::<_, Object>(
                &credential_jpt,
                &document,
                &JptCredentialValidationOptions::default(),
                FailFast::FirstError,
              )
              .unwrap();
        
              (document, decoded_jpt)
        });

    // A unique random challenge generated by the requester per presentation can mitigate replay attacks.
    let challenge: &str = "475a7984-1bb5-4c4c-a56f-822bccd46440";

    group.bench_function("BLS12-381-SHAKE-256 - (ALL attributes disclosed)", |b| b.to_async(&tokio).iter(|| async {
            create_presented_jwp(challenge, &decoded_jpt, &document, 0).await;
        }
        
    ));


    let presentation_jpt = tokio::runtime::Runtime::new().unwrap().block_on(async { create_presented_jwp(challenge, &decoded_jpt, &document, 0).await });



    group.bench_function("Decode/Verify - BLS12-381-SHAKE-256 - (ALL attributes disclosed)", |b| b.to_async(&tokio).iter(|| async {
        let presentation_validation_options = JptPresentationValidationOptions::default().nonce(challenge.clone());

        // Verifier validate the Presented Credential and retrieve the JwpPresented
        let decoded_presented_credential = JptPresentationValidator::validate::<_, Object>(
            &presentation_jpt,
            &document,
            &presentation_validation_options,
            FailFast::FirstError,
        )
        .unwrap();
        }
        
    ));



    // A0 undisclosed

    group.bench_function("BLS12-381-SHAKE-256 - (A0 undisclosed)", |b| b.to_async(&tokio).iter(|| async {
        create_presented_jwp(challenge, &decoded_jpt, &document, 1).await;
    }
    
    ));


    let presentation_jpt = tokio::runtime::Runtime::new().unwrap().block_on(async { create_presented_jwp(challenge, &decoded_jpt, &document, 0).await });
 


    group.bench_function("Decode/Verify - BLS12-381-SHAKE-256 - (A0 undisclosed)", |b| b.to_async(&tokio).iter(|| async {
        let presentation_validation_options = JptPresentationValidationOptions::default().nonce(challenge.clone());

        // Verifier validate the Presented Credential and retrieve the JwpPresented
        let decoded_presented_credential = JptPresentationValidator::validate::<_, Object>(
            &presentation_jpt,
            &document,
            &presentation_validation_options,
            FailFast::FirstError,
        )
        .unwrap();
        }
        
    ));


    // A0 + A1 undisclosed

    group.bench_function("BLS12-381-SHAKE-256 - (A0 + A1 undisclosed)", |b| b.to_async(&tokio).iter(|| async {
        create_presented_jwp(challenge, &decoded_jpt, &document, 2).await;
    }
    
    ));


    let presentation_jpt = tokio::runtime::Runtime::new().unwrap().block_on(async { create_presented_jwp(challenge, &decoded_jpt, &document, 0).await });



    group.bench_function("Decode/Verify - BLS12-381-SHAKE-256 - (A0 + A1 undisclosed)", |b| b.to_async(&tokio).iter(|| async {
        let presentation_validation_options = JptPresentationValidationOptions::default().nonce(challenge.clone());

        // Verifier validate the Presented Credential and retrieve the JwpPresented
        let decoded_presented_credential = JptPresentationValidator::validate::<_, Object>(
            &presentation_jpt,
            &document,
            &presentation_validation_options,
            FailFast::FirstError,
        )
        .unwrap();
        }
        
    ));


    // A0 + A1 + A2 undisclosed

    group.bench_function("BLS12-381-SHAKE-256 - (A0 + A1 + A2 undisclosed)", |b| b.to_async(&tokio).iter(|| async {
        create_presented_jwp(challenge, &decoded_jpt, &document, 3).await;
    }
    
    ));


    let presentation_jpt = tokio::runtime::Runtime::new().unwrap().block_on(async { create_presented_jwp(challenge, &decoded_jpt, &document, 0).await });


    group.bench_function("Decode/Verify - BLS12-381-SHAKE-256 - (A0 + A1 + A2 undisclosed)", |b| b.to_async(&tokio).iter(|| async {
        let presentation_validation_options = JptPresentationValidationOptions::default().nonce(challenge.clone());

        // Verifier validate the Presented Credential and retrieve the JwpPresented
        let decoded_presented_credential = JptPresentationValidator::validate::<_, Object>(
            &presentation_jpt,
            &document,
            &presentation_validation_options,
            FailFast::FirstError,
        )
        .unwrap();
        }
        
    ));


    // A0 + A1 + A2 + A3 undisclosed

    group.bench_function("BLS12-381-SHAKE-256 - (A0 + A1 + A2 + A3 undisclosed)", |b| b.to_async(&tokio).iter(|| async {
        create_presented_jwp(challenge, &decoded_jpt, &document, 4).await;
    }
    
    ));


    let presentation_jpt = tokio::runtime::Runtime::new().unwrap().block_on(async { create_presented_jwp(challenge, &decoded_jpt, &document, 0).await });


    group.bench_function("Decode/Verify - BLS12-381-SHAKE-256 - (A0 + A1 + A2 + A3 undisclosed)", |b| b.to_async(&tokio).iter(|| async {
        let presentation_validation_options = JptPresentationValidationOptions::default().nonce(challenge.clone());

        // Verifier validate the Presented Credential and retrieve the JwpPresented
        let decoded_presented_credential = JptPresentationValidator::validate::<_, Object>(
            &presentation_jpt,
            &document,
            &presentation_validation_options,
            FailFast::FirstError,
        )
        .unwrap();
        }
        
    ));


    // A0 + A1 + A2 + A3 + A4 undisclosed

    group.bench_function("BLS12-381-SHAKE-256 - (A0 + A1 + A2 + A3 + A4 undisclosed)", |b| b.to_async(&tokio).iter(|| async {
        create_presented_jwp(challenge, &decoded_jpt, &document, 5).await;
    }
    
    ));


    let presentation_jpt = tokio::runtime::Runtime::new().unwrap().block_on(async { create_presented_jwp(challenge, &decoded_jpt, &document, 0).await });


    group.bench_function("Decode/Verify - BLS12-381-SHAKE-256 - (A0 + A1 + A2 + A3 + A4 undisclosed)", |b| b.to_async(&tokio).iter(|| async {
        let presentation_validation_options = JptPresentationValidationOptions::default().nonce(challenge.clone());

        // Verifier validate the Presented Credential and retrieve the JwpPresented
        let decoded_presented_credential = JptPresentationValidator::validate::<_, Object>(
            &presentation_jpt,
            &document,
            &presentation_validation_options,
            FailFast::FirstError,
        )
        .unwrap();
        }
        
    ));

}


fn test_zkryptium(c: &mut Criterion) {

    let messages = [
        vec![0u8; 100], 
        vec![0u8; 100], 
        vec![0u8; 100], 
        vec![0u8; 100],
        vec![0u8; 100],
        vec![0u8; 100],
        vec![0u8; 100],
        vec![0u8; 100],
        ];


    let mut group = c.benchmark_group("zkryptium - Sign/Verify");
    group.sample_size(1000);
    group.warm_up_time(Duration::from_secs(3));


    let keypair = KeyPair::<BbsBls12381Sha256>::random().unwrap();
    let sk = keypair.private_key();
    let pk = keypair.public_key();

    group.bench_function("BLS12-381-SHA-256 - Sign", |b| b.iter(|| {
            let signature = Signature::<BbsBls12381Sha256>::sign(Some(&messages), sk, pk, None).unwrap();
        }
    ));

    let t = Instant::now();
    let signature = Signature::<BbsBls12381Sha256>::sign(Some(&messages), sk, pk, None).unwrap();
    println!("{}", t.elapsed().as_millis());

    
    group.bench_function("BLS12-381-SHA-256 - Verify", |b| b.iter(|| {
            assert!(signature.verify(pk, Some(&messages), None).is_ok());
        }
    ));

    println!("SK: {}, PK: {}, Sig: {}", sk.to_bytes().len(), pk.to_bytes().len(), signature.to_bytes().len());


    let keypair = KeyPair::<BbsBls12381Shake256>::random().unwrap();
    let sk = keypair.private_key();
    let pk = keypair.public_key();

    group.bench_function("BLS12-381-SHAKE-256 - Sign", |b| b.iter(|| {
            let signature = Signature::<BbsBls12381Shake256>::sign(Some(&messages), sk, pk, None).unwrap();
        }
    ));

    let signature = Signature::<BbsBls12381Shake256>::sign(Some(&messages), sk, pk, None).unwrap();

    group.bench_function("BLS12-381-SHAKE-256 - Verify", |b| b.iter(|| {
            assert!(signature.verify(pk, Some(&messages), None).is_ok());
        }
    ));

    println!("SK: {}, PK: {}, Sig: {}", sk.to_bytes().len(), pk.to_bytes().len(), signature.to_bytes().len());
   

}

criterion_group!(issued_jwp_gen, benchmark_issued_jwp_gen, benchmark_presented_jwp_gen);

criterion_main!(issued_jwp_gen);