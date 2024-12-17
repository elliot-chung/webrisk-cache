import { WebRiskServiceClient, protos } from "@google-cloud/web-risk";
import { getPrefixes } from "webrisk-hash";
import crypto from "node:crypto";

const allTypes = ["malware", "social", "unwanted"]

const ThreatTypes = {
  "malware" : protos.google.cloud.webrisk.v1.ThreatType.MALWARE,
  "social" : protos.google.cloud.webrisk.v1.ThreatType.SOCIAL_ENGINEERING,
  "unwanted" : protos.google.cloud.webrisk.v1.ThreatType.UNWANTED_SOFTWARE,
}

/**
 * This is a class that handles caching the results of calls to the WebRisk API
 * It follows implementation details from google outlined here:
 * https://cloud.google.com/web-risk/docs/update-api
 * 
 * Typical Usage:
 * ```
 * const cache = new WebriskCache(apiKey)
 * 
 * cache.requestDiff("malware")
 * cache.requestDiff("social")
 * cache.requestDiff("unwanted")
 * 
 * const result = await cache.check("https://www.risky-website.com/")
 * console.log(result) // => [ "SOCIAL_ENGINEERING" ]
 * ```
 * @module WebriskCache
 */
class WebriskCache {
  /**
   * Constructs a new WebriskCache object
   * @param {string} apiKey The API key for the WebRisk API
   */
  constructor(apiKey) {
    this.tokens = {
      "malware" : null,
      "social" : null,
      "unwanted" : null,
    }

    this.#updateTimeoutIDs = {
      "malware" : null,
      "social" : null,
      "unwanted" : null,
    }

    this.hits = {
      "positive" : new Map(),
      "negative" : new Map(),
    }

    this.databases = {
      "malware" : new Map(),
      "social" : new Map(),
      "unwanted" : new Map(),
    }

    this.#client = new WebRiskServiceClient({
      apiKey: apiKey,
    });
  }

  #client
  #updateTimeoutIDs

  /**
   * Update the cache according to the specified threat type
   * @param {string} type The threat type to request a diff for: ["malware", "social", "unwanted", "all"]
   * @param {boolean} [reset=false] Whether to reset the database
   * @param {object} [constraint={}] The constraint to use for the diff
   */
  async requestDiff(type, reset=false, constraint= {}) {
    let typeArr
    if (type === "all") {
      typeArr = allTypes
    } else if (allTypes.includes(type)) {
      typeArr = [type]
    } else {
      throw new Error("Threat type string must be one of 'malware', 'social', 'unwanted', or 'all'")
    }

    for (const typeString of typeArr) 
      await this.#requestSingleDiff(typeString, constraint, reset)
  }

  /**
   * Calculate a hash prefix for the specified URI and check if it is in the cache. 
   * If it is, this function will complete a call to the WebRisk API to verify the threat by comparing the full length hashes.
   * The returned array will contain the threat types that match the URI.
   * It will be empty if the URI is safe. 
   * @param {string} uri The URI or hash to check
   * @param {boolean} [isHash=false] Whether the URI is a hash or not
   * @returns {string[]} An array of threat types: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]
   */
  async check(uri, isHash=false) {
    const identifiedThreats = new Set()
    const allFullHashes = isHash ? [Buffer.from(uri, 'hex')] : getPrefixes(uri)

    for (const fullHash of allFullHashes) {
      const typeString = this.hasHash(fullHash)
      const fullHashString = fullHash.toString('hex')
      
      if (allTypes.includes(typeString)) { // Prefix was found in one of the prefix caches
        const prefix = fullHash.subarray(0, 4)
        const prefixString = prefix.toString('hex')
        const request = {
          threatTypes: Object.values(ThreatTypes), // Search all types 
          hashPrefix: prefix,
        }
        
        process.stdout.write("$$$$ network call...")
        const response = (await this.#client.searchHashes(request))[0]
        console.log("Complete!")

        console.log(response)

        for (const threat of response.threats) {
          const hash = threat.hash
          const hashString = hash.toString('hex')
          this.hits["positive"].set(hashString, [threat.expireTime.seconds, threat.threatTypes])
          if (hash.equals(fullHash)) { // Full hashes match, this is a positive hit
            threat.threatTypes.forEach(element => identifiedThreats.add(element));
            
            break
          } 
        }

        this.hits["negative"].set(prefixString, [response.negativeExpireTime.seconds])

      } else if (typeString === "positive") { // Prefix was found in the positive full hash cache
        const hit = this.hits["positive"].get(fullHashString)
        const threatTypes = hit[1]
        threatTypes.forEach(element => identifiedThreats.add(element));
      } 
    }
    return Array.from(identifiedThreats.values()) 
  }

  /**
   * Check if the specified hash is in a cache
   * 
   * ```
   * const result = cache.hasHash(Buffer.from("a1b2c3d4", "hex"))
   * ```
   * @param {Buffer} hash Buffer representing the hash of a uri
   * @returns {string} The database type that the prefix is in
   */
  hasHash(hash) {
    const prefixString = hash.subarray(0, 4).toString('hex')
    const fullHashString = hash.toString('hex')
    if (this.hits["positive"].has(fullHashString)) {
      const [expireTime, _] = this.hits["positive"].get(fullHashString)
      if (expireTime * 1000 < Date.now()) {
        this.hits["positive"].delete(fullHashString)
      } else {
        return "positive"
      }
    } else if (this.hits["negative"].has(prefixString)) {
      const [expireTime, _] = this.hits["negative"].get(prefixString)
      if (expireTime * 1000 < Date.now()) {
        this.hits["negative"].delete(prefixString)
      } else {
        return "negative"
      }
    }

    for (const [typeString, db] of Object.entries(this.databases)) {
      if (db.has(prefixString)) {
        return typeString
      }
    }
    return "none"
  }

  /**
   * Clear all timers
   * 
   * Call this function before exiting the program
   */
  close() {
    for (const timeoutID of Object.values(this.#updateTimeoutIDs)) {
      clearTimeout(timeoutID)
    }
  }

  async #requestSingleDiff(typeString, constraint= {}, reset=false) {
    const c =
      protos.google.cloud.webrisk.v1.ComputeThreatListDiffRequest.Constraints.create(
        constraint
      );
    const request = {
      constraint: c,
      versionToken: reset ? null : this.tokens[typeString],
      threatType: ThreatTypes[typeString],
    };

    process.stdout.write("Free network call...")
    const response = (await this.#client.computeThreatListDiff(request))[0];
    console.log("Complete!")

    console.log(response)

    this.#updateDB(response, typeString)

    const success = this.#validate(typeString, response.checksum.sha256)

    if (success) {
      this.#diffPromise(typeString, response.recommendedNextDiff.seconds)
    } else {
      console.warn("WARNING: Checksum does not match, retrying...")
      await this.#requestSingleDiff(typeString, constraint, true)
    }
  }

  async #diffPromise(typeString, epochTimeDeadline) {
    const now = Math.round(new Date().getTime() / 1000)
    const seconds = epochTimeDeadline - now

    await new Promise(resolve => {
      const timeoutID = setTimeout(resolve, seconds * 1000)
      if (this.#updateTimeoutIDs[typeString]) clearTimeout(this.#updateTimeoutIDs[typeString])
      this.#updateTimeoutIDs[typeString] = timeoutID
    })
    await this.#requestSingleDiff(typeString)
  }

  /**
   * Make updates to local database based on response from API
   * @param { object } response The response object form the API call
   * @param { string } typeString The string corresponding to the type of threat 
   */
  #updateDB(response, typeString) {
    const additions = response.additions
    const removals = response.removals
    if (response.responseType === "DIFF") {
      this.#removeFromDB(typeString, removals)
      this.#addToDB(typeString, additions)

      this.databases[typeString] = new Map([...this.databases[typeString].entries()].sort())    
    } else if (response.responseType === "RESET") {
      this.databases[typeString].clear()

      this.#addToDB(typeString, additions)
    }
    this.tokens[typeString] = response.newVersionToken
  }

  #removeFromDB(typeString, removals) {
    if (removals) {
      process.stdout.write("\tRemoving from DB...")
      const rawIndices = removals.rawIndices.indices
      const keys = this.databases[typeString].keys()
      const toDelete = []
      for (let i = 0; i < this.databases[typeString].size; i++) {
        const key = keys.next().value
        if (rawIndices.includes(i)) {
          toDelete.push(key)
        }
      }
      toDelete.forEach(x => this.databases[typeString].delete(x))
      console.log("Complete!")
    } 
  }

  #addToDB(typeString, additions) {
    if (additions) {
      process.stdout.write("\tAdding to DB...")
      for (const raw of additions.rawHashes) {
        const buffer = raw.rawHashes
        const prefixSize = raw.prefixSize

        for (let i = 0; i < buffer.length; i+= prefixSize) {
          const prefix = buffer.subarray(i, i+prefixSize)
          const prefixString = prefix.toString('hex')
          this.databases[typeString].set(prefixString, prefix)
        }
      }
      console.log("Complete!")
    }
  }

  #validate(typeString, hashBuffer) {
    const db = this.databases[typeString]
    const d = db.values()
    const b = Buffer.concat([...d])

    const hash = crypto.createHash('sha256').update(b).digest('hex'); // Local DB Hash
    const hash2 = hashBuffer.toString('hex'); // API Hash

    return hash === hash2
  }

  /**
   * Print the tokens for the different threat types
   */
  printTokens() {
    console.log("TOKENS:");
    for (const [key, value] of Object.entries(this.tokens)) {
      console.log(key, value);
    }
  }

  /**
   * Print the malware database
   */
  printMalwareDB() {
    console.log("MALWARE DB:");
    for (const [key, value] of this.databases["malware"].entries()) {
      console.log(key, value);
    }
  }

  /**
   * Print the social engineering database
   */
  printSocialDB() {
    console.log("SOCIAL DB:");
    for (const [key, value] of this.databases["social"].entries()) {
      console.log(key, value);
    }
  }

  /**
   * Print the unwanted software database
   */
  printUnwantedDB() {
    console.log("UNWANTED DB:");
    for (const [key, value] of this.databases["unwanted"].entries()) {
      console.log(key, value);
    }
  }

  /**
   * Print the confirmed hits database
   */
  printHits() {
    console.log("POSITIVE HITS:");
    for (const [key, value] of this.hits["positive"].entries()) {
      console.log(key, value);
    }
    console.log("NEGATIVE HITS:");
    for (const [key, value] of this.hits["negative"].entries()) {
      console.log(key, value);
    }
  }
}

export default WebriskCache;
