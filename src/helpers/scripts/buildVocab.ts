import { mkdirSync, writeFileSync } from 'fs'
import { join } from 'path'
import {
  OE_VOCABULARY_BASE_URI,
  oecVocabularyToContext,
  oecVocabularyToHtml,
  oecVocabularyToJsonLd,
  oecVocabularyToRdf
} from '../../@types/oecVocabulary.js'

// Writes the public vocabulary files served at https://oceanenterprise.io/vocab/
// Usage: node dist/helpers/scripts/buildVocab.js [outDir]   (default: ./vocab)
const outDir = process.argv[2] || 'vocab'
mkdirSync(outDir, { recursive: true })

writeFileSync(join(outDir, 'vocab.ttl'), oecVocabularyToRdf(OE_VOCABULARY_BASE_URI))
writeFileSync(
  join(outDir, 'vocab.jsonld'),
  JSON.stringify(oecVocabularyToJsonLd(OE_VOCABULARY_BASE_URI), null, 2) + '\n'
)
writeFileSync(
  join(outDir, 'context.jsonld'),
  JSON.stringify(
    { '@context': oecVocabularyToContext(OE_VOCABULARY_BASE_URI) },
    null,
    2
  ) + '\n'
)
writeFileSync(join(outDir, 'index.html'), oecVocabularyToHtml(OE_VOCABULARY_BASE_URI))

console.log(`Vocabulary written to ${outDir}/`)
