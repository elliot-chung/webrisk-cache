require("dotenv").config()
const readline = require("readline/promises")

let cache
import("./index.mjs").then(module => {
  cache = new module.default(process.env.WEBRISK_API_KEY)
})

main().catch(console.error)

async function main() {
  while (true) {
    if (!cache) {
      await new Promise(resolve => setTimeout(resolve, 1000))
      continue
    }

    const a = await prompt("<WebRisk Testing> ")
    const tokens = a.trim().split(" ");

    if (tokens[0] === "quit") {
      break
    } else if (tokens[0] === "") {
      continue
    } else if (tokens[0] === "reset") {
      await reset(tokens)
    } else if (tokens[0] === "update") {
      await update(tokens)
    } else if (tokens[0] === "check") {
      await check(tokens)
    } else if (tokens[0] === "test") {
      test(tokens)
    } else if (tokens[0] === "debug") {
      debug(tokens)
    } else {
      console.error("Invalid command")
    }
  }
  cache.close()
}

/**
 * Take sentence input, until you press 'Enter'
 * Like C++ cin
 *
 * @param {String} message The message to display
 * @returns {String} The user's input
 */
async function prompt(message) {
  const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
  });

  const answer = await rl.question(message);

  rl.close(); // stop listening
  return answer;
};

async function reset(tokens) {
  if (tokens.length === 1) {
    await cache.requestDiff("all", true)
  } else {
    const type = tokens[1]
    try {
      await cache.requestDiff(type, true)
    } catch (error) {
      console.error(error.message)
    }
  }
}

async function update(tokens) {
  if (tokens.length === 1) {
    await cache.requestDiff("all")
  } else {
    const type = tokens[1]
    try {
      await cache.requestDiff(type)
    } catch(error) {
      console.error(error.message)
    }
  }
}

async function check(tokens) {
  if (tokens.length < 2) {
    console.error("Must provide input uri to check")
    return
  }
  
  const uri = tokens[1]
  const isHash = tokens[2] === "true"
  const result = await cache.check(uri, isHash)

  console.log("Identified Threats: " + result)
}

async function test(tokens) {
  if (tokens.length < 2) {
    console.error("Must provide prefix to check")
    return
  }
  const prefix = tokens[1]
  const buf = Buffer.from(prefix, "hex")
  const res = cache.findHash(buf)
  console.log("Found in DB: " + res[0])
}

async function debug(tokens) {
  if (tokens.length < 2) {
    cache.printTokens()
    cache.printMalwareDB()
    cache.printSocialDB()
    cache.printUnwantedDB()
  } else {
    if (tokens[1] === "tokens")
      cache.printTokens()
    else if (tokens[1] === "malware")
      cache.printMalwareDB()
    else if (tokens[1] === "social")
      cache.printSocialDB()
    else if (tokens[1] === "unwanted")
      cache.printUnwantedDB()
    else if (tokens[1] === "hits")
      cache.printHits()
    else if (tokens[1] === "sizes")
      cache.printPrefixSizes()
    else
      console.error("Invalid command")
  }
}

