# Webrisk Cache
This is a NodeJS implementation of Google's Webrisk Update API cache. Google's Webrisk API is designed to flag dangerous URIs for malware, social engineering, or unwanted software. The Update API specifically makes it so the client can reference this massive database of URIs with as few network calls as possible. This is enabled by hashing all the problematic URIs and allowing the client to maintain a databases of all the hash prefixes. When checking a new URI, it's hash is computed and the prefix is checked to see if it exists in the local database. If it is, and only if it is, does the client finally make a network call to Google's servers to confirm that the URI is indeed malicious. 

## Usage
```
const cache = new WebriskCache(apiKey)

cache.requestDiff("malware")
cache.requestDiff("social")
cache.requestDiff("unwanted")

const result = await cache.check("https://www.risky-website.com/")
console.log(result) // => [ "SOCIAL_ENGINEERING" ]

cache.close()
```
- This module requires an API key from Google to use the Webrisk Update API
- The first diff must be requested by the user since this first call can take a significant amount of time (As the name implies, these are diffs so subsequent calls should take less time)
- Since this is based on a REST API, the module does not hold open any network connections. The purpose of `cache.close()` is to stop the timers that control update/eviction timing. Otherwise, the cache would never fully leave scope and program will not end. 

## Cache Invalidation
Response from calls to Google's API return reccomended lifetimes for all the data held in cache. This module automatically updates its databases and evicts old items according to these recommendations from Google. 

## Implementation Details
The implementation follows closely with the details outlined by Google in their documentation [here](https://cloud.google.com/web-risk/docs/update-api)

Canonicalizing and hashing URIs was implemented by the library [webrisk-hash](https://github.com/Short-io/webrisk-hash) by Short-io