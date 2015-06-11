
import unicode
import math
import strutils
import times

include constants

iterator unicodeLettersGenerator(): string {.closure.} = 
  for i in 0..high(int16):
    if isAlpha(Rune(i)):
      yield $(Rune(i))

var ch = newSeq[string]()

const
  AsciiLower* = "abcdefghijklmnopqrstuvwxyz"
  AsciiUpper* = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  AsciiLetters* = AsciiLower & AsciiUpper
  Digits* = "0123456789"
  HexDigitsLower* = AsciiLower[0..5] & Digits
  HexDigits* = AsciiUpper[0..5] & AsciiLower[0..5] & Digits
  OctDigits* = Digits[0..7]

for i in unicodeLettersGenerator():
  ch.add(i)

let UnicodeLetters* = ch

proc runeInRange(s: string): Rune =
  result = runeAt(s, random(len(s)))

proc gensa(s: string, length: int): string =
  assert(length > 0)
  result = ""
  var rseq = newSeq[Rune]()
  for i in 0..<length:
    rseq.add(runeInRange(s))
  result = $rseq

proc genAlpha*(length = 10): string =
  result = gensa(AsciiLetters, length)

proc genAlphanumeric*(length = 10): string =
  result = gensa(AsciiLetters & Digits, length)

proc genChoice*[T](choices: openarray[T]): T =
  assert(len(choices) >= 1, "choices cannot be empty")

  if len(choices) == 1:
    result = choices[0]
  else:
    result = choices[random(len(choices))]

proc randInRange(min, max: int): int {.inline.} =
  result = random(max - min + 1) + min

proc genBool*(): bool =
  result = genChoice([true, false])

proc genUniInRange(low, high, length: int): string {.inline.} =
  assert(length > 0)
  var rseq = newSeq[Rune](length)
  for i in 0..<length:
    rseq[i] = Rune(randInRange(low, high))
  result = $rseq

proc genUniInRange(low, high: int, exceptFor: openarray[int],
    length: int): string {.inline.} =
  assert(length > 0)
  var rseq = newSeq[Rune](length)
  for i in 0..<length:
    if i in exceptFor:
      continue
    rseq[i] = Rune(randInRange(low, high))
  result = $rseq

proc genCjk*(length = 10): string =
  ## Returns a random string made up of CJK characters
  result = genUniInRange(0x4e00, 0x9fcc, length)

proc genCyrillic*(length = 10): string =
  ## Returns a random string made up of Cyrillic characters
  result = genUniInRange(0x0400, 0x04ff, length)

proc genEmail*(name, domain, tlds: string = ""): string =
  var (nm,dm,tl) = (name, domain, tlds)
  # get a new name if we need it
  if nm == "":
    nm = genAlpha(8)
  # obtain a random domain if needed
  if dm == "":
    dm = genChoice(Subdomains)
  # obtain a random top-level domain if needed
  if tl == "":
    tl = genChoice(Tlds)

  result = nm & "@" & dm & "." & tl

proc genIpsum*(words = 0, paragraphs: int): string =
  var w = words
  if w == 0:
    w = len(LoremIpsum.split(' '))
  # original string
  var allWordsOrig = LoremIpsum.split(' ')
  let totalWordsNeeded = words * paragraphs

  let quotient = int(totalWordsNeeded div len(allWordsOrig))
  let modulus = totalWordsNeeded mod len(allWordsOrig)
  var allWords = newSeq[string]()

  for i in 0..<(quotient + modulus):
    allWords.add(allWordsOrig)

  result = ""
  var startPos = 0

  for i in 0..<paragraphs:
    var sentence = join(allWords[startPos..(startPos+words-1)], " ")
    # remove comma from end, if it exists
    if sentence[^1] == ',': sentence = sentence[0..^2]
    # remove period from the end, if it exists
    if sentence[^1] == '.': sentence = sentence[0..^2]

    # each sentence should be properly capitalized
    var frags = sentence.split(". ")
    var capSentence = newSeq[string]()
    for i in frags:
      capSentence.add(i.capitalize())

    # add newline at the end
    result &= join(capSentence, " ") & "\n"

    inc startPos, words

proc genLatin1*(length = 10): string =
  ## Returns a random string made up of UTF-8 characters
  assert(length > 0)

  result = genUniInRange(0x00c0,0x00ff,[0x00d7,0x00f7],length)

proc genIpaddr*(ip3 = false, ipv6 = false, prefix: seq[string] = nil): string =
  ## Generates a random IP address
  var rng: int
  if ipv6:
    rng = 8
  elif ip3:
    rng = 3
  else:
    rng = 4

  var pfx = newSeq[string]()
  for field in prefix:
    pfx.add($field)

  rng -= len(pfx)

  if rng == 0:
    raise newException(ValueError, "Prefix " & $(@prefix) & " would lead to " &
      "no randomness at all")
  elif rng < 0:
    raise newException(ValueError, "Prefix " & $(@prefix) & " is too long " &
      "for this configuration")

  var randomFields = newSeq[string]()
  var ipaddr = ""
  if ipv6:
    for i in 0..<rng:
      randomFields.add(randInRange(0, (1 shl 16 - 1)).toHex(4).toLower())
    ipaddr = join(pfx & randomFields, ":")
  else:
    for i in 0..<rng:
      randomFields.add($randInRange(0, 255))
    ipaddr = join(pfx & randomFields, ".")
    if ip3:
      ipaddr = ipaddr & ".0"

  result = ipaddr

proc genIpaddr*(ip3 = false, ipv6 = false, prefix: openarray[int]): string =
  var pfx = newSeq[string]()
  for i in prefix:
    pfx.add($i)
  result = genIpaddr(ip3, ipv6, pfx)

proc genMac*(delimiter = ":"): string =
  ## Generates a random MAC address
  assert (delimiter in ":-", "Delimiter not valid")
  let chars = HexDigitsLower
  result = ""

  # this is a crappy way to do it, but i'm tired
  for _ in 0..<6:
    result &= chars[randInRange(0,len(chars))] & 
              chars[randInRange(0,len(chars))] & delimiter
  result = result[0..^2]

proc genNetmask*(minCidr = 1, maxCidr = 31): string =
  ## Generates a random valid netmask
  assert(minCidr >= 0, "minCidr must be 0 or greater")
  assert(maxCidr < len(ValidNetmasks), "maxCidr must be < 32")
  result = ValidNetmasks[randInRange(minCidr, maxCidr)]

proc genNumericString*(length = 10): string =
  ## Returns a random string made up of numbers
  assert(length > 0)
  result = ""
  for i in 0..<length:
    result = result & genChoice(['0','1','2','3','4','5','6','7','8','9'])

proc genTime*(): TimeInfo =
  ## Generates a random time and returns a TimeInfo object
  var ti = TimeInfo(
    second: random(59),
    minute: random(59),
    hour: random(23),
    monthday: randInRange(1, 31),
    year: randInRange(1900,9999),
    month: Month(random(11)),
    weekday: WeekDay(random(6)),
    yearday: random(365),
    isDst: genBool(),
    tzname: "GMT",
    timezone: 5
  )
  result = ti

proc genUrl*(): string =
  let scheme = genChoice(Schemes)
  let subdomain = genChoice(Subdomains)
  let tld = genChoice(Tlds)

  result = scheme & "://" & subdomain & "." & tld

proc genUtf8*(length = 10): string =
  ## Returns a random string made up of UTF-8 letters characters
  ## CJK seems to dominate the ranges, which makes sense
  assert(length > 0)
  result = ""
  for i in 0..<length:
    result.add(genChoice(UnicodeLetters))

proc genHtml*(length = 10): string =
  ## Returns a random string made up of html characters
  assert(length > 0)

  let htmlTag = genChoice(HtmlTags)
  result = "<$1>$2</$3>".format(htmlTag, genAlpha(length), htmlTag)

proc genUuid*(valid = true): string =
  ## Returns a random UUID
  ## `valid` makes sure some of it makes sense. It doesn't actually make
  ## sure it lines up with valid UUID versions
  let
    part1 = gensa(HexDigitsLower, 8)
    part2 = gensa(HexDigitsLower, 4)
    part5 = gensa(HexDigitsLower, 12)
    
  var part3, part4: string

  if valid:
    part3 = genChoice(['1','2','3','4','5']) & 
            gensa(HexDigitsLower, 3)
  else:
    part3 = gensa(HexDigitsLower, 4)

  if valid:
    part4 = genChoice(['8','9','a','b']) &
            gensa(HexDigitsLower, 3)
  else:
    part4 = gensa(HexDigitsLower, 4)

  let allParts = [part1, part2, part3, part4, part5]
  result = join(allParts, "-")
