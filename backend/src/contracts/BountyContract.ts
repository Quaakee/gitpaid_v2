import {
    assert,
    ByteString,
    PubKey,
    Sig,
    SmartContract,
    prop,
    method,
    hash256,
    Utils,
    pubKey2Addr,
    SigHash
} from 'scrypt-ts'

/**
 * A minimal contract for GitHub events-based bounties.
 * 
 * Key points:
 *  - "repoOwner" has ECDSA pubkey for the repo/organization.
 *  - "certServerKey" is your Metanet cert server's ECDSA public key. 
 *  - We accept "repoOwnerSig" for transaction-level authorization 
 *    (they are spending the UTXO).
 *  - We accept "certServerSig" for verifying the user actually 
 *    solved the GH event, as declared by the server.
 */
export class BountyContract extends SmartContract {

    @prop(true)
    repoOwner: PubKey

    @prop(true)
    certServerKey: PubKey

    constructor(repoOwner: PubKey, certServerKey: PubKey) {
        super(...arguments)
        this.repoOwner = repoOwner
        this.certServerKey = certServerKey
    }

    /**
     * Let the repo owner add more funds into the contract.
     * The new transaction has total UTXO value = old + newly added.
     */
    @method()
    public addFunds() {
        const out = this.buildStateOutput(this.ctx.utxo.value)
        const outputs = out + this.buildChangeOutput()
        assert(hash256(outputs) == this.ctx.hashOutputs, 'hashOutputs mismatch')
    }

    /**
     * Pay a user for a specific GH event. 
     * 
     * @param repoOwnerSig   ECDSA signature from the repoOwner for spending
     * @param certServerSig  ECDSA signature from your cert server 
     * @param userPubKey     The public key of dev who solved it
     * @param eventID        Which GH event/issue is being paid out
     * @param amount         How much the dev is paid
     */
    @method()
    public payBounty(
        repoOwnerSig: Sig,
        certServerSig: Sig,
        userPubKey: PubKey,
        eventID: ByteString,
        amount: bigint
    ) {
        // 1) Check the repoOwner's ECDSA signature for authorizing spend:
        assert(
            this.checkSig(repoOwnerSig, this.repoOwner),
            'Repo Owner signature invalid.'
        )

        // 2) Some "certificate server" verification:
        //
        //    We'll do minimal logic: we rely on "serverPubKey" 
        //    to confirm the server signed this transaction. 
        //    Typically you'd parse “(eventID + userPubKey)” from 
        //    some custom message. This is a placeholder:
        assert(
            this.checkSig(certServerSig, this.certServerKey),
            'Cert server signature invalid.'
        )

        // For a real production version, 
        // you'd incorporate parse or message-hash logic to confirm 
        // the serverSig exactly ties "eventID" to "userPubKey."

        // 3) Enough funds:
        assert(amount <= this.ctx.utxo.value, 'Insufficient funds')

        // 4) Pay user
        const devAddr = pubKey2Addr(userPubKey)
        let outputs = Utils.buildPublicKeyHashOutput(devAddr, amount)

        // leftover locked in contract
        const remain = this.ctx.utxo.value - amount
        if (remain > 0n) {
            outputs += this.buildStateOutput(remain)
        }

        // change for fees
        outputs += this.buildChangeOutput()

        // 5) Must match exactly
        assert(hash256(outputs) == this.ctx.hashOutputs, 'hashOutputs mismatch')
    }

    /**
     * Let the repo owner withdraw leftover bounty if 
     * the bounty is no longer needed.
     */
    @method()
    public withdraw(repoOwnerSig: Sig, amount: bigint) {
        // check signature
        assert(
            this.checkSig(repoOwnerSig, this.repoOwner),
            'Invalid repo owner signature.'
        )

        // enough funds?
        assert(amount <= this.ctx.utxo.value, 'Not enough funds')

        // pay the repoOwner
        const ownerAddr = pubKey2Addr(this.repoOwner)
        let outputs = Utils.buildPublicKeyHashOutput(ownerAddr, amount)

        // leftover
        const leftover = this.ctx.utxo.value - amount
        if (leftover > 0n) {
            outputs += this.buildStateOutput(leftover)
        }

        outputs += this.buildChangeOutput()
        assert(hash256(outputs) == this.ctx.hashOutputs, 'hashOutputs mismatch')
    }
}