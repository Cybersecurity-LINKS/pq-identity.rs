// SPDX-License-Identifier: Apache-2.0

import {
    IotaDID,
    IotaDocument,
    IotaIdentityClient,
    JwkMemStore,
    JwsAlgorithm,
    KeyIdMemStore,
    MethodScope,
    Storage,
    CoreDocument
} from "@iota/identity-wasm/node";
import { AliasOutput, Client, MnemonicSecretManager, SecretManager, Utils } from "@iota/sdk-wasm/node";
import { API_ENDPOINT, ensureAddressHasFunds } from "../util";

/** Demonstrate how to create a DID JWK Document */
export async function createDidJwkPq(){

    const mnemonicSecretManager: MnemonicSecretManager = {
        mnemonic: Utils.generateMnemonic(),
    };

    const storage: Storage = new Storage(new JwkMemStore(), new KeyIdMemStore());
    const document = await CoreDocument.newDidJwkPq(
        storage,
        JwkMemStore.mldsaKeyType(),
        JwsAlgorithm.MLDSA44)

    console.log(JSON.stringify(document, null, 2));
}
