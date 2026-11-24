use poseidon::poseidon2::Poseidon2;

global DOMAIN_ZKA_SPENDING: Field =
    0x14046af3b2a955bb4c450d1b53ffc2798acc3c2924c3519cf923146b775acc67;
global DOMAIN_ZKA_VIEWING: Field =
    0x041a8f7dfa88f8b20fd899a83e0bce075c65856e12e7706113f0b326a9b13eff;
global DOMAIN_ZKA_PROOF: Field = 0x193befdd9db847abcc0c6412a4044f4ce9b378786241eab30fbb50b9faaad2d7;
global DOMAIN_ZKA_ADDRESS: Field =
    0x001b916d980f2edf145af8615825a58890f9ff48dc7c0fa92ed14fe0cd5e5fb8;
global DOMAIN_ZKC_CREDENTIAL: Field =
    0x3010b194aeae94550e7a48d065d9dc931108c2d15136704bf4ad78eae07f0e26;
global DOMAIN_ZKC_BINDING: Field =
    0x12b8b6de2c8fc6b63102155d15c31799845a1f360ab0df6266284bde48e3a93f;

fn h2(a: Field, b: Field) -> Field {
    Poseidon2::hash([a, b], 2)
}

fn assert_kdc(
    seed: Field,
    spending_key: Field,
    viewing_key: Field,
    proof_key: Field,
    address: Field,
    credential_binding_key: Field,
    holder_commitment: Field,
) {
    let sk = h2(DOMAIN_ZKA_SPENDING, seed);
    let vk = h2(DOMAIN_ZKA_VIEWING, sk);
    let pk = h2(DOMAIN_ZKA_PROOF, sk);
    let addr = h2(DOMAIN_ZKA_ADDRESS, vk);
    let cbk = h2(DOMAIN_ZKC_CREDENTIAL, seed);
    let hc = h2(DOMAIN_ZKC_BINDING, cbk);
    assert(sk == spending_key, "spendingKey drift");
    assert(vk == viewing_key, "viewingKey drift");
    assert(pk == proof_key, "proofKey drift");
    assert(addr == address, "address drift");
    assert(cbk == credential_binding_key, "credentialBindingKey drift");
    assert(hc == holder_commitment, "holderCommitment drift");
}

#[test]
fn raw_sponge_edge_and_arity_vectors() {
    let empty: [Field; 0] = [];
    assert(
        Poseidon2::hash(empty, 0)
            == 0x18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e,
    );
    assert(
        Poseidon2::hash([1], 1)
            == 0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373,
    );
    assert(
        Poseidon2::hash([1, 2], 2)
            == 0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383,
    );
    assert(
        Poseidon2::hash([1, 2, 3], 3)
            == 0x23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8,
    );
    assert(
        Poseidon2::hash([1, 2, 3, 4], 4)
            == 0x130bf204a32cac1f0ace56c78b731aa3809f06df2731ebcf6b3464a15788b1b9,
    );
    assert(
        Poseidon2::hash([1, 2, 3, 4, 5, 6], 6)
            == 0x07f57fcda925c06dc0a311f3f17fa0218e079b514552744a25ba8a74ee8c9e7a,
    );
    assert(
        Poseidon2::hash([1, 2, 3, 4, 5, 6, 7], 7)
            == 0x16f929bc0d216df4b05bdc44222463edf2b9791bd949ab926eebda06a502d238,
    );
}

#[test]
fn shared_kdc_boundary_vectors() {
    assert_kdc(
        0,
        0x182877c456caaec9e58390c15c8001c817b8566d8952afd55e5484edbe68363c,
        0x01a4f9348723ddb88b8cb51bfefa165779b20a0595bcb728fcb56a65b3115575,
        0x292019ef1768ba0fa512e5ad8442592135ba8c6fcc75824b68858e518771985c,
        0x1e59072f0fac351c5c4e80a8291ec26d58ef4aaf766c8206cd7ca677b0a9b5a5,
        0x214266e62f30fbe36989a56722253ef4b4f05c73e7e6e79561523f86bbc0bf69,
        0x26911baa3a91df3ae99b57264dd8ffc1a774b75adb6bc44f801eab9a28dbb85c,
    );
    assert_kdc(
        1,
        0x144fa23c717e08e4e14147010d31e2aadd3e7ebb761198d4cbaae23f62b3ef67,
        0x16b8d89ff569ae13d9dc795f0dc70fe3283bc0c9fd66367ea39616d716a33a5d,
        0x23817d38a9dd9cee841fe099e73e3bdf7dc94877661df70d6ce7bede7f741846,
        0x0f26d097b8cdb6e1a28dcb476c9ba0404139ccb92567f2ea3bc2136c70e00bfe,
        0x156363709184916cfd39a0ff03728d2f61eeb21db527764a632ced26248620a9,
        0x1b5da79c042b6f60628ca40f9f36af41ba93a4e0706f18d63918ead501bded10,
    );
    assert_kdc(
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000,
        0x2aa6de3a01fec0825909dae75f37e1b6093ba378df2965185d135fcd0f6fd421,
        0x116d9a4fe480c1d976f48d0122a49fe919de71e813719fa3514bbfd629ab1e02,
        0x0bb78d04ccc163c139ff540e6a28ec440ae3e391a19c294b0ee525fad07bd648,
        0x2f5f49c1a110fc0afaf2757591deb20e1826e1790fb815eed0f371f255fdef01,
        0x0f9ae0ed0936446399b4d8860ba56fad98f3cde0e234351498f9b47157e47770,
        0x0f93ef96e2e9889be72f147c815effddd4836f6a03c133b9383eaa4c0237d9ae,
    );
    // Seeds r and r+1 map to the already-checked field inputs 0 and 1.
    assert_kdc(
        0x1f37631a3d9cbfac8f5f7492fcfd4f45af982f6f0c8d1edd783c14d81ffffffe,
        0x054bffb9c2753d29eb67714bedaec3f6f909f62d0b6edc3e8b32f5feae599dd1,
        0x17f2e28a96e45b73ffbe05ae5568b726392f10047e1a2b1ed6a8597c5798665f,
        0x2b4003b5718df23357bbbaf25b96eb4cea82405b01d5f8a47d1567a779e76b63,
        0x2cdbe57561dc37866f283823339e4551faffbfa407fc1147bc4db440b8adf826,
        0x2e0ec1d6d13e07e096d6e97072ada506cfd048265c8e715b48cdb52222211acc,
        0x20bdb27ab52177af841502649fae65d8f7ad2456c92afa3392c75e40fd4854e3,
    );
    assert_kdc(
        0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f,
        0x25c8b56ae92ceeb873fdba8ebded92b2da7b03fe6330fd464bc68ef60e43d35c,
        0x302a0ff15a9d16b4f00df3ab76b71a7182b9850d6ec33411515f776f9083ab8d,
        0x01b48895c3cc1bf9626fe911881b27a856f6fe5c7f73587a647cc3095299f1a6,
        0x28424ceb512ed48ac09bb7f7a8965e4e88b4f1401e7d4988b0fb045b9d45e2e8,
        0x13f7a19491d111e859b706bbf4ac09ae04b9ae617fd9810f2c2abc79498b25f7,
        0x168c18b64068e5507de96921fc526999752d8df4413ec276a3ab7cd2b57f6223,
    );
}
