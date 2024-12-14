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

    this.databases = {
      "positiveHit": new Map(),
      "negativeHit": new Map(),
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
   * @param {string} uri The URI to check
   * @returns {string[]} An array of threat types: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]
   */
  async check(uri) {
    const identifiedThreats = new Set()
    const prefixHashes = getPrefixes(uri, 32)

    for (const prefix of prefixHashes) {
      const typeString = this.hasPrefix(prefix)
      if (allTypes.includes(typeString)) {
        const fullHashes = getPrefixes(uri)
        
        const request = {
          threatTypes: Object.values(ThreatTypes), // Search all types 
          hashPrefix: prefix,
        }
        
        process.stdout.write("$$$$ network call...")
        const response = (await this.#client.searchHashes(request))[0]
        console.log("Complete!")

        for (const threat of response.threats) {
          const hash = threat.hash
          for (const hash2 of fullHashes) {
            if (hash.equals(hash2)) {
              threat.threatTypes.forEach(element => identifiedThreats.add(element));
              
              const number = prefix.readUInt32BE(0)
              this.databases["positiveHit"].set(number, [hash, threat.threatTypes, null])
              this.#evictionPromise(number, threat.expireTime.seconds)
              
              break
            }
          } 
        }
      } else if (typeString === "positiveHit") {
        const fullHashes = getPrefixes(uri)
        const number = prefix.readUInt32BE(0)
        const hit = this.databases["positiveHit"].get(number)
        const hash = hit[0]
        const threatTypes = hit[1]
        for (const hash2 of fullHashes) {
          if (hash.equals(hash2)) {
            threatTypes.forEach(element => identifiedThreats.add(element));
            break
          }
        }
      }
    }
    return Array.from(identifiedThreats.values()) 
  }

  /**
   * Check if the specified prefix is in the cache
   * ```
   * const result = cache.hasPrefix(Buffer.from("a1b2c3d4", "hex"))
   * ```
   * @param {Buffer} prefix Buffer containing 4 bytes representing the prefix
   * @returns 
   */
  hasPrefix(prefix) {
    const number = prefix.readUInt32BE(0)
    for (const [typeString, db] of Object.entries(this.databases)) {
      if (db.has(number)) {
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
    for (const list of this.databases["positiveHit"].values()) {
      clearTimeout(list[2])
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
      this.#updateTimeoutIDs[typeString] = timeoutID
    })
    await this.#requestSingleDiff(typeString)
  }

  async #evictionPromise(number, epochTimeDeadline) {
    const now = Math.round(new Date().getTime() / 1000)
    const seconds = epochTimeDeadline - now

    await new Promise(resolve => {
      const timeoutID = setTimeout(resolve, seconds * 1000)
      this.databases["positiveHit"].get(number)[2] = timeoutID
    }) 
    this.databases["positiveHit"].delete(number)
  }

  /**
   * Make updates to local database based on response from API
   * @param { object } response The response object form the API call
   * @param { string } typeString The string corresponding to the type of threat 
   */
  #updateDB(response, typeString) {
    if (response.responseType === "DIFF") {
      const additions = response.additions
      const removals = response.removals

      this.#removeFromDB(typeString, removals)
      this.#addToDB(typeString, additions)

      this.databases[typeString] = new Map([...this.databases[typeString].entries()].sort((a, b) => a[0] - b[0]))    
    } else if (response.responseType === "RESET") {
      this.databases[typeString].clear()

      this.#addToDB(typeString, response.additions)
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
          const prefix = buffer.slice(i, i+prefixSize)
          const number = prefix.readUInt32BE(0)
          this.databases[typeString].set(number, prefix)
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
    console.log("HITS:");
    for (const [key, value] of this.databases["positiveHit"].entries()) {
      console.log(key, value);
    }
  }
}

export default WebriskCache;
