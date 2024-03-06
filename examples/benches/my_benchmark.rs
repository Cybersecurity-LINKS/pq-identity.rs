
use std::collections::HashMap;
use std::mem;
use std::ops::Add;
use std::time::Duration;

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
use identity_iota::credential::DecodedJwtCredential;
use identity_iota::credential::DecodedJwtPresentation;
use identity_iota::credential::FailFast;
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
use identity_iota::storage::JwsDocumentExtPQC;
use identity_iota::storage::JwsSignatureOptions;
use identity_iota::storage::KeyIdMemstore;
use identity_iota::storage::KeyType;
use identity_iota::storage::Storage;
use identity_iota::verification::jws::JwsAlgorithm;
use identity_iota::verification::MethodScope;
use identity_pqc_verifier::PQCJwsVerifier;
use iota_sdk::client::secret::stronghold::StrongholdSecretManager;
use iota_sdk::client::secret::SecretManager;
use iota_sdk::client::Client;
use iota_sdk::client::Password;
use iota_sdk::types::block::address::Address;
use iota_sdk::types::block::output::AliasOutput;
use rand::rngs::mock;
use serde_json::json;
use tokio::runtime::Runtime;
use tokio::task;
use tokio::time::Instant;
use tokio::try_join;

use criterion::*;
use criterion::async_executor::AsyncExecutor;

// The API endpoint of an IOTA node, e.g. Hornet.
// const API_ENDPOINT: &str = "http://192.168.94.191";
const API_ENDPOINT: &str = "https://api.testnet.shimmer.network";
// The faucet endpoint allows requesting funds for testing purposes.
const FAUCET_ENDPOINT: &str = "http://faucet.testnet.shimmer.network/api/enqueue";

// // The API endpoint of an IOTA node, e.g. Hornet.
// const API_ENDPOINT: &str = "http://localhost";
// // The faucet endpoint allows requesting funds for testing purposes.
// const FAUCET_ENDPOINT: &str = "http://localhost/faucet/api/enqueue";


async fn create_did(client: &Client, address: Address, network_name: &NetworkName, secret_manager: &SecretManager, storage: &MemStorage, key_type: KeyType, alg: JwsAlgorithm) -> (Address, IotaDocument, String) {

  // Create a new DID document with a placeholder DID.
  // The DID will be derived from the Alias Id of the Alias Output after publishing.
  let mut document: IotaDocument = IotaDocument::new(network_name);

  // New Verification Method containing a Ed25519 key


  let fragment = if alg == JwsAlgorithm::EdDSA && key_type == JwkMemStore::ED25519_KEY_TYPE {
  
    document.generate_method(
        &storage, 
        key_type, 
        alg, 
        None, 
        MethodScope::VerificationMethod
    ).await.unwrap()

  } else {
    document.generate_method_pqc(
        &storage, 
        key_type, 
        alg, 
        None, 
        MethodScope::VerificationMethod
    ).await.unwrap()

  };


  // Construct an Alias Output containing the DID document, with the wallet address
  // set as both the state controller and governor.
  let alias_output: AliasOutput = client.new_did_output(address, document.clone(), None).await.unwrap();

  // Publish the Alias Output and get the published DID document.
  let document: IotaDocument = client.publish_did_output(&secret_manager, alias_output).await.unwrap();

  (address, document, fragment)
}



struct Input {
    client: Client, 
    secret_manager_issuer: SecretManager, 
    storage_issuer: MemStorage, 
    address: Address, 
    network_name: NetworkName
}

fn criterion_benchmark(c: &mut Criterion) {

    // Create a new client to interact with the IOTA ledger.
    let input = tokio::runtime::Runtime::new().unwrap().block_on(async {
        let client: Client = Client::builder()
            .with_primary_node(API_ENDPOINT, None)
            .unwrap()
            .finish()
            .await
            .unwrap();

        let secret_manager_issuer = SecretManager::Stronghold(StrongholdSecretManager::builder()
        .password(Password::from("secure_password_1".to_owned()))
        .build(random_stronghold_path())
        .unwrap());
    
        let storage_issuer: MemStorage = MemStorage::new(JwkMemStore::new(), KeyIdMemstore::new());
    
        // Get an address with funds for testing.
        let address: Address = get_address_with_funds(&client, &secret_manager_issuer, FAUCET_ENDPOINT).await.unwrap();
    
        // Get the Bech32 human-readable part (HRP) of the network.
        let network_name: NetworkName = client.network_name().await.unwrap();

        Input{client, secret_manager_issuer, storage_issuer, address, network_name}

    });

    let tokio1 = tokio::runtime::Runtime::new().unwrap();

    let tk = tokio::runtime::Builder::new_multi_thread()
    .enable_all()
    .build()
    .unwrap();

    let mut group = c.benchmark_group("DID Create");
    group.sample_size(50);
    group.warm_up_time(Duration::from_secs(3));

    group.bench_function("Ed25519", move |b| b.to_async(&tk).iter_with_large_drop(|| async {
        create_did(
            &input.client, 
            input.address, 
            &input.network_name, 
            &input.secret_manager_issuer, 
            &input.storage_issuer, 
            JwkMemStore::ED25519_KEY_TYPE, 
            JwsAlgorithm::EdDSA
            // black_box(&client), 
            // black_box(address), 
            // black_box(&network_name), 
            // black_box(&secret_manager_issuer), 
            // black_box(&storage_issuer), 
            // black_box(JwkMemStore::ED25519_KEY_TYPE), 
            // black_box(JwsAlgorithm::EdDSA)
        ).await
    }
    ));

    // let tokio2 = tokio::runtime::Runtime::new().unwrap();

    // group.bench_function("ML-DSA-44", |b| b.to_async(&tokio2).iter_with_large_drop(|| async {
    //     create_did(
    //         &client, 
    //         address, 
    //         &network_name, 
    //         &secret_manager_issuer, 
    //         &storage_issuer, 
    //         JwkMemStore::ML_DSA_KEY_TYPE, 
    //         JwsAlgorithm::ML_DSA_44
    //     ).await.unwrap()}
    // ));

    // let tokio3 = tokio::runtime::Runtime::new().unwrap();

    // group.bench_function("ML-DSA-65", |b| b.to_async(&tokio3).iter_with_large_drop(|| async {
    //     create_did(
    //         &client, 
    //         address, 
    //         &network_name, 
    //         &secret_manager_issuer, 
    //         &storage_issuer, 
    //         JwkMemStore::ML_DSA_KEY_TYPE, 
    //         JwsAlgorithm::ML_DSA_65
    //     ).await.unwrap()}
    // ));

    // let tokio4 = tokio::runtime::Runtime::new().unwrap();

    // group.bench_function("ML-DSA-87", |b| b.to_async(&tokio4).iter_with_large_drop(|| async {
    //     create_did(
    //         &client, 
    //         address, 
    //         &network_name, 
    //         &secret_manager_issuer, 
    //         &storage_issuer, 
    //         JwkMemStore::ML_DSA_KEY_TYPE, 
    //         JwsAlgorithm::ML_DSA_87
    //     ).await.unwrap()}
    // ));

    group.finish();
    
}



async fn setup_did_resolve(key_type: KeyType, alg: JwsAlgorithm) -> (Client, IotaDocument) {

    // Create a new client to interact with the IOTA ledger.
    let client: Client = Client::builder()
        .with_primary_node(API_ENDPOINT, None)
        .unwrap()
        .finish()
        .await
        .unwrap();

    let secret_manager_issuer = SecretManager::Stronghold(StrongholdSecretManager::builder()
    .password(Password::from("secure_password_1".to_owned()))
    .build(random_stronghold_path())
    .unwrap());

    let storage_issuer: MemStorage = MemStorage::new(JwkMemStore::new(), KeyIdMemstore::new());

    // Get an address with funds for testing.
    let address: Address = get_address_with_funds(&client, &secret_manager_issuer, FAUCET_ENDPOINT).await.unwrap();

    // Get the Bech32 human-readable part (HRP) of the network.
    let network_name: NetworkName = client.network_name().await.unwrap();

    let (_, document, _) = create_did(
        &client, 
        address, 
        &network_name, 
        &secret_manager_issuer, 
        &storage_issuer, 
        key_type.clone(), 
        alg
    ).await;

(client, document)

}


fn criterion_benchmark_did_resolve(c: &mut Criterion) {

    let (client, doc) = tokio::runtime::Runtime::new().unwrap().block_on(async {
        setup_did_resolve(JwkMemStore::ED25519_KEY_TYPE, JwsAlgorithm::EdDSA).await
    });

    // Resolve the holder's document.
    let mut resolver: Resolver<IotaDocument> = Resolver::new();
    resolver.attach_iota_handler(client);
    let did: CoreDID = CoreDID::parse(doc.id().as_str()).unwrap();

    let tokio = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("Ed25519 - DID Resolve", |b| b.to_async(&tokio).iter(|| async {
        test_resolve_did(
            black_box(&resolver),
            black_box(&did)
        ).await
        }
    ));
}


async fn test_resolve_did(resolver: &Resolver<IotaDocument>, did: &CoreDID) {
        
    resolver.resolve(did).await.unwrap();
}


const MOCK_DOCUMENT_JSON: &str = r#"
{
    "id": "did:bar:Hyx62wPQGyvXCoihZq1BrbUjBRh2LuNxWiiqMkfAuSZr",
    "verificationMethod": [
      {
        "id": "did:bar:Hyx62wPQGyvXCoihZq1BrbUjBRh2LuNxWiiqMkfAuSZr#root",
        "controller": "did:bar:Hyx62wPQGyvXCoihZq1BrbUjBRh2LuNxWiiqMkfAuSZr",
        "type": "Ed25519VerificationKey2018",
        "publicKeyMultibase": "zHyx62wPQGyvXCoihZq1BrbUjBRh2LuNxWiiqMkfAuSZr"
      }
    ]
}"#;

async fn setup(key_type: KeyType, alg: JwsAlgorithm) -> (CoreDocument, MemStorage, String, Credential) {
  let mut mock_document = CoreDocument::from_json(MOCK_DOCUMENT_JSON).unwrap();
  let storage = Storage::new(JwkMemStore::new(), KeyIdMemstore::new());


    let method_fragment = 
    if alg == JwsAlgorithm::EdDSA && key_type == JwkMemStore::ED25519_KEY_TYPE {

        mock_document.generate_method(
            &storage, 
            key_type, 
            alg, 
            None, 
            MethodScope::VerificationMethod
        ).await.unwrap()

        } else {
        mock_document.generate_method_pqc(
            &storage, 
            key_type, 
            alg, 
            None, 
            MethodScope::VerificationMethod
        ).await.unwrap()

        };

  let credential_json: &str = r#"
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "id": "http://example.edu/credentials/3732",
      "type": ["VerifiableCredential", "UniversityDegreeCredential"],
      "issuer": "did:bar:Hyx62wPQGyvXCoihZq1BrbUjBRh2LuNxWiiqMkfAuSZr",
      "issuanceDate": "2010-01-01T19:23:24Z",
      "credentialSubject": {
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "degree": {
          "type": "BachelorDegree",
          "name": "Bachelor of Science in Mechanical Engineering"
        }
      }
    }"#;

  let credential: Credential = Credential::from_json(credential_json).unwrap();

  (mock_document, storage, method_fragment, credential)
}



fn benchmark_vc_create(c: &mut Criterion) {
    let (document, storage, kid, credential) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup(JwkMemStore::ED25519_KEY_TYPE, JwsAlgorithm::EdDSA).await });

    let tokio = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("VC (JWT) Create");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(3));

    println!("VC size = {}", serde_json::to_vec(&credential).unwrap().len());
    
    let mut jwt: Jwt;

    group.bench_function("Ed25519", |b| b.to_async(&tokio).iter(|| async {
        document
        .create_credential_jwt(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap();

        }
    ));

    jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
        .create_credential_jwt(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap()
    });

    println!("Ed25519 - VC (JWT) size = {}", jwt.as_str().as_bytes().len());


    let (document, storage, kid, credential) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup(JwkMemStore::ML_DSA_KEY_TYPE, JwsAlgorithm::ML_DSA_44).await });

    group.bench_function("ML-DSA-44", |b| b.to_async(&tokio).iter(|| async {
        document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap();

        }
    ));


    jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap()
    });

    println!("ML-DSA-44 - VC (JWT) size = {}", jwt.as_str().as_bytes().len());


    let (document, storage, kid, credential) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup(JwkMemStore::ML_DSA_KEY_TYPE, JwsAlgorithm::ML_DSA_65).await });

    group.bench_function("ML-DSA-65", |b| b.to_async(&tokio).iter(|| async {
        document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap();

        }
    ));

    jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap()
    });

    println!("ML-DSA-65 - VC (JWT) size = {}", jwt.as_str().as_bytes().len());

    let (document, storage, kid, credential) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup(JwkMemStore::ML_DSA_KEY_TYPE, JwsAlgorithm::ML_DSA_87).await });

    group.bench_function("ML-DSA-87", |b| b.to_async(&tokio).iter(|| async {
        document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap();

        }
    ));

    jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap()
    });

    println!("ML-DSA-87 - VC (JWT) size = {}", jwt.as_str().as_bytes().len());

    let (document, storage, kid, credential) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup(JwkMemStore::SLH_DSA_KEY_TYPE, JwsAlgorithm::SLH_DSA_SHA2_128s).await });

    group.bench_function("SLH_DSA_SHA2_128s", |b| b.to_async(&tokio).iter(|| async {
        document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap();

        }
    ));

    jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap()
    });

    println!("SLH_DSA_SHA2_128s - VC (JWT) size = {}", jwt.as_str().as_bytes().len());

    let (document, storage, kid, credential) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup(JwkMemStore::SLH_DSA_KEY_TYPE, JwsAlgorithm::SLH_DSA_SHAKE_128s).await });

    group.bench_function("SLH_DSA_SHAKE_128s", |b| b.to_async(&tokio).iter(|| async {
        document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap();

        }
    ));

    jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap()
    });

    println!("SLH_DSA_SHAKE_128s - VC (JWT) size = {}", jwt.as_str().as_bytes().len());

    let (document, storage, kid, credential) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup(JwkMemStore::SLH_DSA_KEY_TYPE, JwsAlgorithm::SLH_DSA_SHA2_128f).await });

    group.bench_function("SLH_DSA_SHA2_128f", |b| b.to_async(&tokio).iter(|| async {
        document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap();

        }
    ));

    jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap()
    });

    println!("SLH_DSA_SHA2_128f - VC (JWT) size = {}", jwt.as_str().as_bytes().len());

    let (document, storage, kid, credential) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup(JwkMemStore::SLH_DSA_KEY_TYPE, JwsAlgorithm::SLH_DSA_SHAKE_128f).await });

    group.bench_function("SLH_DSA_SHAKE_128f", |b| b.to_async(&tokio).iter(|| async {
        document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap();

        }
    ));

    jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap()
    });

    println!("SLH_DSA_SHAKE_128f - VC (JWT) size = {}", jwt.as_str().as_bytes().len());

    let (document, storage, kid, credential) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup(JwkMemStore::SLH_DSA_KEY_TYPE, JwsAlgorithm::SLH_DSA_SHA2_192s).await });

    group.bench_function("SLH_DSA_SHA2_192s", |b| b.to_async(&tokio).iter(|| async {
        document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap();

        }
    ));

    jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap()
    });

    println!("SLH_DSA_SHA2_192s - VC (JWT) size = {}", jwt.as_str().as_bytes().len());

    let (document, storage, kid, credential) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup(JwkMemStore::SLH_DSA_KEY_TYPE, JwsAlgorithm::SLH_DSA_SHAKE_192s).await });

    group.bench_function("SLH_DSA_SHAKE_192s", |b| b.to_async(&tokio).iter(|| async {
        document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap();

        }
    ));

    jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap()
    });

    println!("SLH_DSA_SHAKE_192s - VC (JWT) size = {}", jwt.as_str().as_bytes().len());

    let (document, storage, kid, credential) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup(JwkMemStore::SLH_DSA_KEY_TYPE, JwsAlgorithm::SLH_DSA_SHA2_192f).await });

    group.bench_function("SLH_DSA_SHA2_192f", |b| b.to_async(&tokio).iter(|| async {
        document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap();

        }
    ));

    jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap()
    });

    println!("SLH_DSA_SHA2_192f - VC (JWT) size = {}", jwt.as_str().as_bytes().len());

    let (document, storage, kid, credential) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup(JwkMemStore::SLH_DSA_KEY_TYPE, JwsAlgorithm::SLH_DSA_SHAKE_192f).await });

    group.bench_function("SLH_DSA_SHAKE_192f", |b| b.to_async(&tokio).iter(|| async {
        document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap();

        }
    ));

    jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap()
    });

    println!("SLH_DSA_SHAKE_192f - VC (JWT) size = {}", jwt.as_str().as_bytes().len());

    let (document, storage, kid, credential) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup(JwkMemStore::SLH_DSA_KEY_TYPE, JwsAlgorithm::SLH_DSA_SHA2_256s).await });

    group.bench_function("SLH_DSA_SHA2_256s", |b| b.to_async(&tokio).iter(|| async {
        document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap();

        }
    ));

    jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap()
    });

    println!("SLH_DSA_SHA2_256s - VC (JWT) size = {}", jwt.as_str().as_bytes().len());

    let (document, storage, kid, credential) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup(JwkMemStore::SLH_DSA_KEY_TYPE, JwsAlgorithm::SLH_DSA_SHAKE_256s).await });

    group.bench_function("SLH_DSA_SHAKE_256s", |b| b.to_async(&tokio).iter(|| async {
        document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap();

        }
    ));

    jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap()
    });

    println!("SLH_DSA_SHAKE_256s - VC (JWT) size = {}", jwt.as_str().as_bytes().len());

    let (document, storage, kid, credential) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup(JwkMemStore::SLH_DSA_KEY_TYPE, JwsAlgorithm::SLH_DSA_SHA2_256f).await });

    group.bench_function("SLH_DSA_SHA2_256f", |b| b.to_async(&tokio).iter(|| async {
        document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap();

        }
    ));

    jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap()
    });

    println!("SLH_DSA_SHA2_256f- VC (JWT) size = {}", jwt.as_str().as_bytes().len());


    let (document, storage, kid, credential) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup(JwkMemStore::SLH_DSA_KEY_TYPE, JwsAlgorithm::SLH_DSA_SHAKE_256f).await });

    group.bench_function("SLH_DSA_SHAKE_256f", |b| b.to_async(&tokio).iter(|| async {
        document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap();

        }
    ));

    jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap()
    });

    println!("SLH_DSA_SHAKE_256f - VC (JWT) size = {}", jwt.as_str().as_bytes().len());

    let (document, storage, kid, credential) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup(JwkMemStore::FALCON_KEY_TYPE, JwsAlgorithm::FALCON512).await });

    group.bench_function("FALCON512", |b| b.to_async(&tokio).iter(|| async {
        document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap();

        }
    ));

    jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap()
    });

    println!("FALCON512 - VC (JWT) size = {}", jwt.as_str().as_bytes().len());

    let (document, storage, kid, credential) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup(JwkMemStore::FALCON_KEY_TYPE, JwsAlgorithm::FALCON1024).await });

    group.bench_function("FALCON1024", |b| b.to_async(&tokio).iter(|| async {
        document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap();

        }
    ));

    jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          kid.as_ref(),
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap()
    });

    println!("FALCON1024 - VC (JWT) size = {}", jwt.as_str().as_bytes().len());

    
}




async fn setup_presentation(key_type: KeyType, alg: JwsAlgorithm) -> (CoreDocument, MemStorage, String, Presentation<Jwt>) {
  let mut mock_document = CoreDocument::from_json(MOCK_DOCUMENT_JSON).unwrap();
  let storage = Storage::new(JwkMemStore::new(), KeyIdMemstore::new());


    let method_fragment = 
    if alg == JwsAlgorithm::EdDSA && key_type == JwkMemStore::ED25519_KEY_TYPE {

        mock_document.generate_method(
            &storage, 
            key_type.clone(), 
            alg, 
            None, 
            MethodScope::VerificationMethod
        ).await.unwrap()

        } else {
        mock_document.generate_method_pqc(
            &storage, 
            key_type.clone(), 
            alg, 
            None, 
            MethodScope::VerificationMethod
        ).await.unwrap()

        };

  let credential_json: &str = r#"
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "id": "http://example.edu/credentials/3732",
      "type": ["VerifiableCredential", "UniversityDegreeCredential"],
      "issuer": "did:bar:Hyx62wPQGyvXCoihZq1BrbUjBRh2LuNxWiiqMkfAuSZr",
      "issuanceDate": "2010-01-01T19:23:24Z",
      "credentialSubject": {
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "degree": {
          "type": "BachelorDegree",
          "name": "Bachelor of Science in Mechanical Engineering"
        }
      }
    }"#;

  let credential: Credential = Credential::from_json(credential_json).unwrap();

  let vc_jwt = if alg == JwsAlgorithm::EdDSA && key_type == JwkMemStore::ED25519_KEY_TYPE {

    mock_document
        .create_credential_jwt(
          &credential,
          &storage,
          &method_fragment,
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap()

  } else {
    mock_document
        .create_credential_jwt_pqc(
          &credential,
          &storage,
          &method_fragment,
          &JwsSignatureOptions::default(),
          None
        )
        .await.unwrap()
  };


  // ===========================================================================
  // Step 5: Holder creates and signs a verifiable presentation from the issued credential.
  // ===========================================================================

  // Create an unsigned Presentation from the previously issued Verifiable Credential.
  let presentation: Presentation<Jwt> =
    PresentationBuilder::new(mock_document.id().to_url().into(), Default::default())
      .credential(vc_jwt)
      .build().unwrap();


  (mock_document, storage, method_fragment, presentation)
}



fn benchmark_vp_create(c: &mut Criterion) {
  let (document, storage, kid, presentation) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup_presentation(JwkMemStore::ED25519_KEY_TYPE, JwsAlgorithm::EdDSA).await });
  // A unique random challenge generated by the requester per presentation can mitigate replay attacks.
  let challenge: &str = "475a7984-1bb5-4c4c-a56f-822bccd46440";

  // The verifier and holder also agree that the signature should have an expiry date
  // 10 minutes from now.
  let expires: Timestamp = Timestamp::now_utc().checked_add(Dur::minutes(10)).unwrap();


  let tokio = tokio::runtime::Runtime::new().unwrap();
  let mut group = c.benchmark_group("VP (JWT) Create");
  group.sample_size(10);
  group.warm_up_time(Duration::from_secs(3));

  println!("VP size = {}", serde_json::to_vec(&presentation).unwrap().len());
  
  let mut jwt: Jwt;

  // group.bench_function("Ed25519", |b| b.to_async(&tokio).iter(|| async {
  //     document
  //     .create_presentation_jwt(
  //       &presentation,
  //       &storage,
  //       &kid,
  //       &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //       &JwtPresentationOptions::default().expiration_date(expires),
  //     )
  //     .await.unwrap()

  //     }
  // ));

  // jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {
  //   document
  //   .create_presentation_jwt(
  //     &presentation,
  //     &storage,
  //     &kid,
  //     &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //     &JwtPresentationOptions::default().expiration_date(expires),
  //   )
  //   .await.unwrap()
  // });

  // println!("Ed25519 - VP (JWT) size = {}", jwt.as_str().as_bytes().len());


  // let (document, storage, kid, presentation) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup_presentation(JwkMemStore::ML_DSA_KEY_TYPE, JwsAlgorithm::ML_DSA_44).await });

  // group.bench_function("ML-DSA-44", |b| b.to_async(&tokio).iter(|| async {
  //   document
  //   .create_presentation_jwt_pqc(
  //     &presentation,
  //     &storage,
  //     &kid,
  //     &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //     &JwtPresentationOptions::default().expiration_date(expires),
  //   )
  //   .await.unwrap()

  //     }
  // ));


  // jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
  //   .create_presentation_jwt_pqc(
  //     &presentation,
  //     &storage,
  //     &kid,
  //     &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //     &JwtPresentationOptions::default().expiration_date(expires),
  //   )
  //   .await.unwrap()
  // });

  // println!("ML-DSA-44 - VP (JWT) size = {}", jwt.as_str().as_bytes().len());


  // let (document, storage, kid, presentation) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup_presentation(JwkMemStore::ML_DSA_KEY_TYPE, JwsAlgorithm::ML_DSA_65).await });

  // group.bench_function("ML-DSA-65", |b| b.to_async(&tokio).iter(|| async {
  //   document
  //   .create_presentation_jwt_pqc(
  //     &presentation,
  //     &storage,
  //     &kid,
  //     &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //     &JwtPresentationOptions::default().expiration_date(expires),
  //   )
  //   .await.unwrap()

  //     }
  // ));

  // jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
  //   .create_presentation_jwt_pqc(
  //     &presentation,
  //     &storage,
  //     &kid,
  //     &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //     &JwtPresentationOptions::default().expiration_date(expires),
  //   )
  //   .await.unwrap()
  // });

  // println!("ML-DSA-65 - VP (JWT) size = {}", jwt.as_str().as_bytes().len());

  // let (document, storage, kid, presentation) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup_presentation(JwkMemStore::ML_DSA_KEY_TYPE, JwsAlgorithm::ML_DSA_87).await });

  // group.bench_function("ML-DSA-87", |b| b.to_async(&tokio).iter(|| async {
  //   document
  //   .create_presentation_jwt_pqc(
  //     &presentation,
  //     &storage,
  //     &kid,
  //     &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //     &JwtPresentationOptions::default().expiration_date(expires),
  //   )
  //   .await.unwrap()

  //     }
  // ));

  // jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
  //   .create_presentation_jwt_pqc(
  //     &presentation,
  //     &storage,
  //     &kid,
  //     &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //     &JwtPresentationOptions::default().expiration_date(expires),
  //   )
  //   .await.unwrap()
  // });

  // println!("ML-DSA-87 - VP (JWT) size = {}", jwt.as_str().as_bytes().len());

  let (document, storage, kid, presentation) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup_presentation(JwkMemStore::SLH_DSA_KEY_TYPE, JwsAlgorithm::SLH_DSA_SHA2_128s).await });

  // group.bench_function("SLH_DSA_SHA2_128s", |b| b.to_async(&tokio).iter(|| async {
  //   document
  //   .create_presentation_jwt_pqc(
  //     &presentation,
  //     &storage,
  //     &kid,
  //     &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //     &JwtPresentationOptions::default().expiration_date(expires),
  //   )
  //   .await.unwrap()
  //     }
  // ));

  jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
    .create_presentation_jwt_pqc(
      &presentation,
      &storage,
      &kid,
      &JwsSignatureOptions::default().nonce(challenge.to_owned()),
      &JwtPresentationOptions::default().expiration_date(expires),
    )
    .await.unwrap()
  });

  println!("T = {}", jwt.as_str());

  // println!("SLH_DSA_SHA2_128s - VP (JWT) size = {}", jwt.as_str().as_bytes().len());

  let (document, storage, kid, presentation) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup_presentation(JwkMemStore::SLH_DSA_KEY_TYPE, JwsAlgorithm::SLH_DSA_SHAKE_128s).await });

  // group.bench_function("SLH_DSA_SHAKE_128s", |b| b.to_async(&tokio).iter(|| async {
  //   document
  //   .create_presentation_jwt_pqc(
  //     &presentation,
  //     &storage,
  //     &kid,
  //     &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //     &JwtPresentationOptions::default().expiration_date(expires),
  //   )
  //   .await.unwrap()

  //     }
  // ));

  jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
    .create_presentation_jwt_pqc(
      &presentation,
      &storage,
      &kid,
      &JwsSignatureOptions::default().nonce(challenge.to_owned()),
      &JwtPresentationOptions::default().expiration_date(expires),
    )
    .await.unwrap()
  });

  println!("T = {}", jwt.as_str());

  // println!("SLH_DSA_SHAKE_128s - VP (JWT) size = {}", jwt.as_str().as_bytes().len());

  // let (document, storage, kid, presentation) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup_presentation(JwkMemStore::SLH_DSA_KEY_TYPE, JwsAlgorithm::SLH_DSA_SHA2_128f).await });

  // group.bench_function("SLH_DSA_SHA2_128f", |b| b.to_async(&tokio).iter(|| async {
  //   document
  //   .create_presentation_jwt_pqc(
  //     &presentation,
  //     &storage,
  //     &kid,
  //     &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //     &JwtPresentationOptions::default().expiration_date(expires),
  //   )
  //   .await.unwrap()
  //     }
  // ));

  // jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
  //   .create_presentation_jwt_pqc(
  //     &presentation,
  //     &storage,
  //     &kid,
  //     &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //     &JwtPresentationOptions::default().expiration_date(expires),
  //   )
  //   .await.unwrap()
  // });

  // println!("SLH_DSA_SHA2_128f - VP (JWT) size = {}", jwt.as_str().as_bytes().len());

  // let (document, storage, kid, presentation) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup_presentation(JwkMemStore::SLH_DSA_KEY_TYPE, JwsAlgorithm::SLH_DSA_SHAKE_128f).await });

  // group.bench_function("SLH_DSA_SHAKE_128f", |b| b.to_async(&tokio).iter(|| async {
  //   document
  //   .create_presentation_jwt_pqc(
  //     &presentation,
  //     &storage,
  //     &kid,
  //     &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //     &JwtPresentationOptions::default().expiration_date(expires),
  //   )
  //   .await.unwrap()
  //     }
  // ));

  // jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
  //   .create_presentation_jwt_pqc(
  //     &presentation,
  //     &storage,
  //     &kid,
  //     &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //     &JwtPresentationOptions::default().expiration_date(expires),
  //   )
  //   .await.unwrap()
  // });

  // println!("SLH_DSA_SHAKE_128f - VP (JWT) size = {}", jwt.as_str().as_bytes().len());

  let (document, storage, kid, presentation) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup_presentation(JwkMemStore::SLH_DSA_KEY_TYPE, JwsAlgorithm::SLH_DSA_SHA2_192s).await });

  group.bench_function("SLH_DSA_SHA2_192s", |b| b.to_async(&tokio).iter(|| async {
    document
    .create_presentation_jwt_pqc(
      &presentation,
      &storage,
      &kid,
      &JwsSignatureOptions::default().nonce(challenge.to_owned()),
      &JwtPresentationOptions::default().expiration_date(expires),
    )
    .await.unwrap()
      }
  ));

  jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
    .create_presentation_jwt_pqc(
      &presentation,
      &storage,
      &kid,
      &JwsSignatureOptions::default().nonce(challenge.to_owned()),
      &JwtPresentationOptions::default().expiration_date(expires),
    )
    .await.unwrap()
  });

  println!("SLH_DSA_SHA2_192s - VP (JWT) size = {}", jwt.as_str().as_bytes().len());

  // let (document, storage, kid, presentation) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup_presentation(JwkMemStore::SLH_DSA_KEY_TYPE, JwsAlgorithm::SLH_DSA_SHAKE_192s).await });

  // group.bench_function("SLH_DSA_SHAKE_192s", |b| b.to_async(&tokio).iter(|| async {
  //   document
  //   .create_presentation_jwt_pqc(
  //     &presentation,
  //     &storage,
  //     &kid,
  //     &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //     &JwtPresentationOptions::default().expiration_date(expires),
  //   )
  //   .await.unwrap()
  //     }
  // ));

  // jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
  //   .create_presentation_jwt_pqc(
  //     &presentation,
  //     &storage,
  //     &kid,
  //     &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //     &JwtPresentationOptions::default().expiration_date(expires),
  //   )
  //   .await.unwrap()
  // });

  // println!("SLH_DSA_SHAKE_192s - VP (JWT) size = {}", jwt.as_str().as_bytes().len());

  // let (document, storage, kid, presentation) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup_presentation(JwkMemStore::SLH_DSA_KEY_TYPE, JwsAlgorithm::SLH_DSA_SHA2_192f).await });

  // group.bench_function("SLH_DSA_SHA2_192f", |b| b.to_async(&tokio).iter(|| async {
  //   document
  //   .create_presentation_jwt_pqc(
  //     &presentation,
  //     &storage,
  //     &kid,
  //     &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //     &JwtPresentationOptions::default().expiration_date(expires),
  //   )
  //   .await.unwrap()

  //     }
  // ));

  // jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
  //   .create_presentation_jwt_pqc(
  //     &presentation,
  //     &storage,
  //     &kid,
  //     &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //     &JwtPresentationOptions::default().expiration_date(expires),
  //   )
  //   .await.unwrap()
  // });

  // println!("SLH_DSA_SHA2_192f - VP (JWT) size = {}", jwt.as_str().as_bytes().len());

  // let (document, storage, kid, presentation) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup_presentation(JwkMemStore::SLH_DSA_KEY_TYPE, JwsAlgorithm::SLH_DSA_SHAKE_192f).await });

  // group.bench_function("SLH_DSA_SHAKE_192f", |b| b.to_async(&tokio).iter(|| async {
  //   document
  //   .create_presentation_jwt_pqc(
  //     &presentation,
  //     &storage,
  //     &kid,
  //     &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //     &JwtPresentationOptions::default().expiration_date(expires),
  //   )
  //   .await.unwrap()

  //     }
  // ));

  // jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
  //   .create_presentation_jwt_pqc(
  //     &presentation,
  //     &storage,
  //     &kid,
  //     &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //     &JwtPresentationOptions::default().expiration_date(expires),
  //   )
  //   .await.unwrap()
  // });

  // println!("SLH_DSA_SHAKE_192f - VP (JWT) size = {}", jwt.as_str().as_bytes().len());

  let (document, storage, kid, presentation) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup_presentation(JwkMemStore::SLH_DSA_KEY_TYPE, JwsAlgorithm::SLH_DSA_SHA2_256s).await });

  group.bench_function("SLH_DSA_SHA2_256s", |b| b.to_async(&tokio).iter(|| async {
    document
    .create_presentation_jwt_pqc(
      &presentation,
      &storage,
      &kid,
      &JwsSignatureOptions::default().nonce(challenge.to_owned()),
      &JwtPresentationOptions::default().expiration_date(expires),
    )
    .await.unwrap()

      }
  ));

  jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
    .create_presentation_jwt_pqc(
      &presentation,
      &storage,
      &kid,
      &JwsSignatureOptions::default().nonce(challenge.to_owned()),
      &JwtPresentationOptions::default().expiration_date(expires),
    )
    .await.unwrap()
  });

  println!("SLH_DSA_SHA2_256s - VP (JWT) size = {}", jwt.as_str().as_bytes().len());

  // let (document, storage, kid, presentation) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup_presentation(JwkMemStore::SLH_DSA_KEY_TYPE, JwsAlgorithm::SLH_DSA_SHAKE_256s).await });

  // group.bench_function("SLH_DSA_SHAKE_256s", |b| b.to_async(&tokio).iter(|| async {
  //   document
  //   .create_presentation_jwt_pqc(
  //     &presentation,
  //     &storage,
  //     &kid,
  //     &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //     &JwtPresentationOptions::default().expiration_date(expires),
  //   )
  //   .await.unwrap()
  //     }
  // ));

  // jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
  //   .create_presentation_jwt_pqc(
  //     &presentation,
  //     &storage,
  //     &kid,
  //     &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //     &JwtPresentationOptions::default().expiration_date(expires),
  //   )
  //   .await.unwrap()
  // });

  // println!("SLH_DSA_SHAKE_256s - VP (JWT) size = {}", jwt.as_str().as_bytes().len());

  // let (document, storage, kid, presentation) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup_presentation(JwkMemStore::SLH_DSA_KEY_TYPE, JwsAlgorithm::SLH_DSA_SHA2_256f).await });

  // group.bench_function("SLH_DSA_SHA2_256f", |b| b.to_async(&tokio).iter(|| async {
  //   document
  //   .create_presentation_jwt_pqc(
  //     &presentation,
  //     &storage,
  //     &kid,
  //     &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //     &JwtPresentationOptions::default().expiration_date(expires),
  //   )
  //   .await.unwrap()
  //     }
  // ));

  // jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
  //   .create_presentation_jwt_pqc(
  //     &presentation,
  //     &storage,
  //     &kid,
  //     &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //     &JwtPresentationOptions::default().expiration_date(expires),
  //   )
  //   .await.unwrap()
  // });

  // println!("SLH_DSA_SHA2_256f- VP (JWT) size = {}", jwt.as_str().as_bytes().len());


  // let (document, storage, kid, presentation) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup_presentation(JwkMemStore::SLH_DSA_KEY_TYPE, JwsAlgorithm::SLH_DSA_SHAKE_256f).await });

  // group.bench_function("SLH_DSA_SHAKE_256f", |b| b.to_async(&tokio).iter(|| async {
  //   document
  //   .create_presentation_jwt_pqc(
  //     &presentation,
  //     &storage,
  //     &kid,
  //     &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //     &JwtPresentationOptions::default().expiration_date(expires),
  //   )
  //   .await.unwrap()
  //     }
  // ));

  // jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
  //   .create_presentation_jwt_pqc(
  //     &presentation,
  //     &storage,
  //     &kid,
  //     &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //     &JwtPresentationOptions::default().expiration_date(expires),
  //   )
  //   .await.unwrap()
  // });

  // println!("SLH_DSA_SHAKE_256f - VP (JWT) size = {}", jwt.as_str().as_bytes().len());

  // let (document, storage, kid, presentation) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup_presentation(JwkMemStore::FALCON_KEY_TYPE, JwsAlgorithm::FALCON512).await });

  // group.bench_function("FALCON512", |b| b.to_async(&tokio).iter(|| async {
  //   document
  //   .create_presentation_jwt_pqc(
  //     &presentation,
  //     &storage,
  //     &kid,
  //     &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //     &JwtPresentationOptions::default().expiration_date(expires),
  //   )
  //   .await.unwrap()
  //     }
  // ));

  // jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
  //   .create_presentation_jwt_pqc(
  //     &presentation,
  //     &storage,
  //     &kid,
  //     &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //     &JwtPresentationOptions::default().expiration_date(expires),
  //   )
  //   .await.unwrap()
  // });

  // println!("FALCON512 - VP (JWT) size = {}", jwt.as_str().as_bytes().len());

  // let (document, storage, kid, presentation) = tokio::runtime::Runtime::new().unwrap().block_on(async { setup_presentation(JwkMemStore::FALCON_KEY_TYPE, JwsAlgorithm::FALCON1024).await });

  // group.bench_function("FALCON1024", |b| b.to_async(&tokio).iter(|| async {
  //   document
  //   .create_presentation_jwt_pqc(
  //     &presentation,
  //     &storage,
  //     &kid,
  //     &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //     &JwtPresentationOptions::default().expiration_date(expires),
  //   )
  //   .await.unwrap()
  //     }
  // ));

  // jwt = tokio::runtime::Runtime::new().unwrap().block_on(async {document
  //   .create_presentation_jwt_pqc(
  //     &presentation,
  //     &storage,
  //     &kid,
  //     &JwsSignatureOptions::default().nonce(challenge.to_owned()),
  //     &JwtPresentationOptions::default().expiration_date(expires),
  //   )
  //   .await.unwrap()
  // });

  // println!("FALCON1024 - VP (JWT) size = {}", jwt.as_str().as_bytes().len());

  
}





criterion_group!(vp_create_benches, benchmark_vp_create);

criterion_group!(vc_create_benches, benchmark_vc_create);

criterion_group!(benches, criterion_benchmark, benchmark_vc_create);

criterion_main!(vp_create_benches);