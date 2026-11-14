# Documentation style: ASD-STE100 Simplified Technical English

All technical documentation in the D-Modem project uses ASD-STE100
Simplified Technical English (STE). This guide gives the rules that we use.
It applies to READMEs, the `docs/` folders, wikis, specifications, design
documents, protocol write-ups, CONTRIBUTING files (except legal text) and
technical notes in the project files.

The official source is the ASD-STE100 specification (Issue 9) and its
dictionary. If this guide and the specification are different, use the
specification. You can get the specification free of charge from
<https://www.asd-ste100.org>.

## 1. What STE does not change

Do not change these items. Copy them exactly:

- Code, commands, file names, paths, URLs, identifiers and configuration keys.
- AT commands, S-registers, result codes and protocol message names.
- Numbers, units, addresses, offsets and register values.
- Titles of standards (for example, ITU-T V.92) and quotations from them.
- Product names, company names and the names of people.
- Legal text: licenses, the contributor agreement, copyright and trademark
  notices. Legal text keeps its legal wording.
- Text that we copied from a third party (for example, `ORIGINAL-readme.txt`
  files, firmware release notes, test fixtures).

## 2. Words

1. Use approved words from the STE dictionary, with their approved meaning
   only. For example, "close" means "to move to the closed position". It
   does not mean "near".
2. Use technical names (Category: technical names). For example: modem,
   handshake, carrier, codec, constellation, packet, socket, thread,
   buffer, firmware, sample rate, call, line, PBX, trunk, server, client.
3. Use technical verbs (Category: technical verbs) for processes that STE
   does not cover. This project uses these technical verbs: build, compile,
   link, configure, install, uninstall, boot, flash, download, upload, dial,
   log in, log out, debug, decode, encode, modulate, demodulate, train,
   retrain, negotiate, sign, encrypt, decrypt, compress, decompress, parse,
   render, cache, merge, commit, push, clone, emulate, probe.
4. Use one word for one thing. Do not change between synonyms. For example,
   if you write "softmodem", do not write "software modem" in the next
   paragraph.
5. Use these verb forms only: infinitive, imperative, simple present, simple
   past, simple future, and the past participle as an adjective.
6. Do not use "-ing" forms of verbs, except in technical names (for example,
   "ring signal", "echo canceller"). Write "the modem starts to train", not
   "the modem is training".
7. Do not use phrasal verbs. Write "start", not "start up". Write "find",
   not "find out".
8. Do not make noun clusters of more than three words. Use prepositions to
   break up longer clusters. Write "the receive buffer of the V.34 data
   pump", not "the V.34 data pump receive buffer".
9. Use articles ("the", "a") and demonstrative adjectives ("this", "these")
   before nouns where possible.
10. Do not use slang, idioms, contractions ("can't", "it's") or Latin
    abbreviations ("e.g.", "i.e.", "etc."). Write "for example", "that is",
    "and other items".

### Common replacements

| Do not write | Write |
|---|---|
| utilize, make use of | use |
| ensure, make certain | make sure |
| require, need to | is necessary, must |
| should | must (a rule) or write what occurs (a fact) |
| allow, enable (a person) | let, make it possible |
| approximately, roughly | about |
| perform, carry out | do |
| obtain, fetch, grab | get |
| prior to | before |
| in order to | to |
| via | through |
| currently | now |
| additional | more |
| e.g., i.e., etc. | for example, that is, and other items |
| turn on / turn off (a setting) | enable / disable (technical verbs for software settings) |
| set up (verb) | configure, install |
| figure out, find out | find, calculate |
| it's, can't, don't | it is, cannot, do not |

## 3. Sentences

1. Write one topic in one sentence.
2. Procedural sentences (instructions): 20 words or fewer.
3. Descriptive sentences: 25 words or fewer.
4. Use the active voice. In descriptive text, you can use the passive voice
   only when you do not know who or what does the action.
5. Do not use semicolons to join sentences. Write two sentences.
6. Use a colon before a list. Use a vertical list when there are more than
   two items.
7. Use connecting words ("then", "but", "if", "because") to show how two
   sentences are related.

## 4. Procedures

1. Write instructions in the imperative ("Install the package").
2. Write one instruction in one sentence. You can write two actions in one
   sentence only when the reader does them at the same time.
3. Write each step as a numbered item.
4. If a condition applies, write the condition first: "If the build fails,
   delete the `build/` folder."
5. Put a warning or a caution before the step that it applies to. Do not put
   it at the end of the procedure.
6. Write the result of a step in a separate sentence after the step, if the
   reader must know it.

## 5. Descriptive writing

1. Give the most important information first.
2. Write one topic in one paragraph.
3. Do not write more than six sentences in a paragraph.
4. Use headings to divide long text into short sections.
5. Use tables for data that has rows and columns.

## 6. Warnings and cautions

Use a warning for a risk to persons. Use a caution for a risk to equipment,
data or the telephone line. Start with a short title, then the instruction,
then the risk:

> **CAUTION: DO NOT CONNECT THE BOARD TO A LIVE LINE WITHOUT THE ISOLATION
> TRANSFORMER.** The line voltage can cause damage to the codec.

## 7. Examples

| Before | After (STE) |
|---|---|
| You'll need to make sure the PBX is set up before you dial out. | Configure the PBX before you dial. |
| The handshake is performed by the answering modem, which then starts sending ANSam. | The answering modem starts the handshake. Then it sends ANSam. |
| Turn it off if it's causing trouble. | If this feature causes problems, disable it. |
| `crypto/tls` can't take such a hello, and it can't be rewritten for it. | `crypto/tls` cannot accept this type of hello. Also, you cannot change `crypto/tls` to accept it. |

## 8. Check before you commit

- Are all sentences short (20 words for instructions, 25 for descriptions)?
- Is each instruction in the imperative, with one action?
- Is there a word with "-ing", a phrasal verb or a contraction?
- Are code, commands and identifiers exactly the same as before?
- Did you keep legal text and third-party text unchanged?
