import os, sys, string, re, collections, operator, copy, time, timeit, linecache, heapq

cipherAlphabet = None
top_ten_solutions = []

def find_all_occurrences(string, substr):
    """ find all occurences of a substring """
    return [m.start() for m in re.finditer(substr, string)]

def english_ness(text):
    score = 0
    
    bigrams = ['TH', 'HE', 'IN', 'ER', 'AN', 'RE', 'ND', 'ON', 'EN', 'AT', 'OU', 'ED', 'HA', 'TO', 'OR', 'IT', 'IS', 'HI', 'ES', 'NG']
    
    trigrams = ['THE', 'AND', 'ING', 'HER', 'HAT', 'HIS', 'THA', 'ERE', 'FOR', 'ENT', 'ION', 'TER', 'WAS', 'YOU', 'ITH', 'VER', 'ALL', 'WIT', 'THI', 'TIO']
    
    quadrigrams = ['THAT', 'THER', 'WITH', 'TION', 'HERE', 'OULD', 'IGHT', 'HAVE', 'HICH', 'WHIC', 'THIS', 'THIN', 'THEY', 'ATIO', 'EVER', 'FROM', 'OUGH', 'WERE', 'HING', 'MENT']
    
    for k in bigrams:
        occ = find_all_occurrences(text, k)
        score += len(occ)
    
    for k in trigrams:
        occ = find_all_occurrences(text, k)
        score += len(occ) * 2
        
    for k in quadrigrams:
        occ = find_all_occurrences(text, k)
        score += len(occ) * 3

    words = text.split(' ')
            
    # get all one letter words
    one_letter_words = [w for w in words if len(w) == 1]
    if 'A' in one_letter_words or 'I' in one_letter_words:
        score += 3
        
    # look for digraph patterns
    digraph = {
        'H': ['CH', 'SH', 'TH', 'PH', 'WH'],
        'K': ['CK', 'SK', 'LK', 'KE'],
        'Q': ['QU'],
        'X': ['EX']   
    }
    
    # Only two vowels, 'E' and 'O', are commonly used as double-letter vowel digraphs
    # especially so in 3- and 4-letter words
    three_and_4_letter_words = [w for w in words if len(w) == 3 or len(w) == 4]
    
    points = 0
    for w in three_and_4_letter_words:
        if w.find('EE') != -1 or w.find('OO') != -1:
            points += 2

    score += points
    
    # common prefixes and suffixes
    prefixes = ['DE', 'DIS', 'EN', 'EM', 'IN', 'IM', 'MIS', 'OVER', 'PRE', 'RE', 'UN']
    suffixes = ['ABLE', 'AL', 'ED', 'EN', 'ER', 'EST',\
     'FUL', 'IBLE', 'IC', 'ING', 'ION', 'IVE', 'LESS',\
     'LY', 'MENT', 'NESS', 'OUS', 'TION', 'ATION' 'ITION',\
     'OUS', 'IOUS', 'EOUS', 'ATIOUS', 'ITIOUS', 'ATIVE', 'ITIVE']
    points = 0
    matchedPrefixes = [p for w in words for p in prefixes if w.startswith(p)]
    for w in matchedPrefixes:
        points += len(w) # longer prefixes get more points
    
    matchedSuffixes = [p for w in words for s in suffixes if w.endswith(s)]
    for w in matchedSuffixes:
        points += len(w) # same for longer suffixes

    score += points
    # Some Tell-Tale Word Patterns
    # A--A--
    # ALWAYS
    # -E-E-
    # NEVER
    # -EO--E
    # PEOPLE
    # -E--EE-
    # BETWEEN
    # E-E--
    # EVERY
    # E-E-
    # EVEN or EVER        
    
    return score

class BackwardsReader:
    """Read a file line by line, backwards"""
    BLKSIZE = 4096

    def readline(self):
        while 1:
            newline_pos = string.rfind(self.buf, "\n")
            pos = self.file.tell()
            if newline_pos != -1:
                # Found a newline
                line = self.buf[newline_pos+1:]
                self.buf = self.buf[:newline_pos]
                if pos != 0 or newline_pos != 0 or self.trailing_newline:
                    line += "\n"
                return line
            else:
                if pos == 0:
                    # Start-of-file
                    return ""
                else:
                    # Need to fill buffer
                    toread = min(self.BLKSIZE, pos)
                    self.file.seek(-toread, 1)
                    self.buf = self.file.read(toread) + self.buf
                    self.file.seek(-toread, 1)
                    if pos - toread == 0:
                        self.buf = "\n" + self.buf

    def __init__(self, file):
        self.file = file
        self.buf = ""
        self.file.seek(-1, 2)
        self.trailing_newline = 0
        lastchar = self.file.read(1)
        if lastchar == "\n":
            self.trailing_newline = 1
            self.file.seek(-1, 2)   
    
    def seek(self, i):
        self.file.seek(i)


def decrypt(solution, ciphertext):
    plaintext = ''
    keys = solution.keys()
    
    # iterate and replace each character
    for c in ciphertext:
        if c == ' ':
            p = ' '
        elif c in keys:
            p = solution[c]
        else:
            p = '#'
        
        plaintext += p
    return plaintext

def getLetterPattern(word):
    """ Converts a word to a letter pattern """
    
    pattern = ''
    alphabet = string.uppercase
    d = {}
    i = 0
    for letter in word:
        if letter not in d.keys():
            d[letter] = alphabet[i]
            i += 1
    for letter in word:
        pattern += d[letter]
    return pattern

    
def isConsistent(Map, C, P):
    """ 
    Map: current cipher-to-plaintext mapping
    C: cipherword
    P: potential candidate for C
    
    When we say that a map is consistent with a word mapping, we mean two things:
    1) No encoded letter maps to two different letters
    2) No decoded letter is mapped to twice. 
    
    """
    
    for i, X in enumerate(C):
        if P[i] not in Map[X]: # alternatively, Map[X].keys()
            return False
    return True

def addMappings(NewMap, C, P):
    for i, X in enumerate(C):
        NewMap[X][P[i]] = P[i]
    
    return NewMap

def plannerSelectUnknownLetterOrWord():
    pass
    
def getSamePatternWords(target, f):
    """ get a list of words that have the same letter pattern as the target word """
    
    # find words with targetPattern before pos    
    pos = f.tell()
    targetPattern = getLetterPattern(target)
    br = BackwardsReader(f)
    br.seek(pos-1)
    candidates = []
    while 1:
        word = br.readline()[:-1]
        pattern = getLetterPattern(word)

        if pattern != targetPattern:
            break
        else:
            candidates.insert(0, word) # insert word to the front

    # find words with targetPattern after pos
    f.seek(pos)
    while 1:
        word = f.readline()[:-1]
        pattern = getLetterPattern(word)
        if pattern != targetPattern:
            break
        candidates.append(word)

    return candidates

def getCandidates(C, f):
    f.seek(0, os.SEEK_END)
    bytes = f.tell()
    candidates = []
    key = getLetterPattern(C)
    left, right = 0, bytes-1
    search = None
    f.seek(0)

    while key != search and left <= right:
      mid = (left + right) / 2
      f.seek(mid)

      # now realign to a record
      b = None
      x = mid-1
      while x > 0 and b != '\n':
          f.seek(x)
          b = f.read(1)
          x -= 1

      line = f.readline()
      word = line[:-1]
      search = getLetterPattern(word)
      if search == key: # found
        candidates = getSamePatternWords(word, f)
        return candidates

      elif search > key:
          right = f.tell()-len(line)-1
      else: # search < key
          left = f.tell()+1

def initMap():
    Map = {}
    for x in cipherAlphabet:
        Map[x] = {letter : letter for letter in string.uppercase }
        
    return Map

def intersect(Map, NewMap):
    """ """
    
    reductionPerformed = False
    
    for x in Map.iterkeys():
        if NewMap[x] == {}: continue
        
        oldSize = len(Map[x])
        Map[x] = {letter : letter for letter in (set(Map[x]) & set(NewMap[x])) }
        if oldSize > len(Map[x]):
            reductionPerformed = True
    
    return Map, reductionPerformed;


def selfIntersection(Map, cipherwords, candidateLists, firstCandIndices):
    """ """
    
    while 1:
        for C in cipherwords:
            NewMap = {}
            for X in cipherAlphabet:
                NewMap[X] = {}

            patt = getLetterPattern(C)
            candidates = candidateLists[ patt ]
            newCandList = []
            # candidates = getCandidates(C, candidateListFile)
            
            for i, P in enumerate(candidates):
                if i < firstCandIndices[ patt ]: continue
                
                if isConsistent(Map, C, P):
                    NewMap = addMappings(NewMap, C, P)
            
            # print NewMap
            Map, reductionPerformed = intersect(Map, NewMap)
            # print NewMap
            
        if not reductionPerformed: # map has reached "steady-state", i.e., until no more reductions are possible
            break
    return Map

def reportFullSolution(cipherwords, Map):
    print 'reportFullSolution'
    solution = {}
    for X in cipherAlphabet:
        solution[X] = Map[X].values()[0]
    print Map
    
    print decrypt(solution, ' '.join(cipherwords))

def updateTopTenSolutions(m, score):
    if len(top_ten_solutions) < 10:
        heapq.heappush(top_ten_solutions, (-score, m))
    else:
        top = heapq.heappop(top_ten_solutions)
        if top[0] < score:
            heapq.heappush(top_ten_solutions, (-score, m))
            return True
        else:
            heapq.heappush(top_ten_solutions, top)
            return False

def reportPartialSolution(Map):
    print 'reportPartialSolution'
    # print Map
    solution = {}
    for X in cipherAlphabet:
        solution[X] = Map[X].values()[0]
    
    m = decrypt(solution, ' '.join(cipherwords))
    score = english_ness(m)
    
    # if(updateTopTenSolutions(m, score)):
    
    if score > 100:
        print 'Score:', score
        print m
    
def allCipherTextKnown(Map):
    """ All ciphertext mappings found if and only if there is 1-to-1 mapping 
    for each alphabet from cipher to plaintext """
    
    for X in cipherAlphabet:
        if len(Map[X]) > 1:
            return False
    return True

def getNumLetterMappings(word):
    d = {}
    cnt = 0
    for l in word:
        if l not in d.keys():
            d[l] = 1
            cnt += 1
    return cnt

def searchReorder(cipherwords):
    """ consider words with more letter mappings first """
    cipherwords.sort(lambda x,y: -cmp(getNumLetterMappings(x), getNumLetterMappings(y)))
    return cipherwords

def assign(Map, C, P):
    for i in range(len(C)):
        Map[C[i]] = { P[i] : P[i] } 
        
def bar(Map, distinctCipherWords, candidateLists, firstCandIndices):
    assign(Map, "HCAU", "KEPT")
    Map = selfIntersection(Map, distinctCipherWords, candidateLists, firstCandIndices)
    print Map['H']

def unscramble(cipherwords):
    # initial preparation
    distinctCipherWords = searchReorder(list(set(cipherwords)))
    candidateLists, firstCandIndices = createCandidateLists(distinctCipherWords)
    
    # start search tree
    solveRecursive(distinctCipherWords, 0, initMap(), candidateLists, firstCandIndices)  
    print 'end'

def solveRecursive(distinctCipherWords, depth, Map, candidateLists, firstCandIndices):
    # if depth == len(cipherwords)-1: # all cipherwords known
    if allCipherTextKnown(Map):
        reportFullSolution(cipherwords, Map)
        sys.exit(1)
    
    if depth == len(cipherwords)-1:
        return
    
    #C = plannerSelectUnknownLetterOrWord()

    hasChild = False
    C = cipherwords[depth]
    patt = getLetterPattern(C)
    Map = selfIntersection(Map, distinctCipherWords, candidateLists, firstCandIndices)    
    candidates = candidateLists[ patt ]

    # candidates = getCandidates(C, candidateListFile)
    
    for i, P in enumerate(candidates):
        if isConsistent(Map, C, P):
            # newMap = addMappings(Map.copy(), C, P)
            newMap = Map.copy()
            assign(newMap, C, P)
            solveRecursive(cipherwords, depth+1, newMap, candidateLists, firstCandIndices)
            hasChild = True
            
    if not hasChild:
        reportPartialSolution(Map)
        
    # re-enable all candidates disabled at this node
    # firstCandIndices[ patt ] = oldFirstCand

def createCandidateLists(distinctCipherWords):
    freq_words_file = open('most-common-english-words.txt')
    word_rank = collections.defaultdict(lambda: sys.maxint) # here, higher number => lower rank
    for rank, line in enumerate(freq_words_file):
        word_rank[ line[:-1] ] = rank

    freq_words_file.close()
    
    def sortByLetterPatternAndWordFreq(word_1, word_2):
        p1 = getLetterPattern(word_1)
        p2 = getLetterPattern(word_2)
        
        if p1 < p2:
            return -1
        elif p1 > p2:
            return 1
        else:
            return word_rank[ word_1 ] - word_rank[ word_2 ]
    
    # candidateList = []
    dict_file = open('words-sorted-by-pattern')    
    candidateLists = {}
    firstCandIndices = {}
    
    for w in distinctCipherWords:
        patt = getLetterPattern(w)
        
        if patt not in candidateLists.keys():
            candidateLists[ patt ] = getCandidates(w, dict_file)
            firstCandIndices[ patt ] = 0
            # candidateList += getCandidates(w, dict_file)
    
    dict_file.close()
    
            
    # candidateList.sort(cmp=sortByLetterPatternAndWordFreq)
    
    # # write candidate lists to an external file
    # outf = open('cand-lists', 'w')
    # # firstCandIndices.append(1) # start at line 1
    # firstCandIndices.append(0)
    # prev_patt = getLetterPattern( candidateList[0])
    # outf.write(candidateList[0] + '\n')
    # curr_patt = None
    # # idx = 2 
    # idx = 1
    # for P in (candidateList[1:]):
    #     curr_patt = getLetterPattern(P)
    #     if prev_patt != curr_patt:
    #         firstCandIndices.append(idx)
    #         prev_patt = curr_patt
    #         
    #     idx += 1
    #     
    #     outf.write(P + '\n')

    # free up the memory for candidate lists (which could be sizeable)
    # del candidateList
    
    # outf.close()
    
    # return pointer to the file that was just created and the list of first candidate indices
    # f = open('cand-lists')
    # return f, firstCandIndices
    
    # for simplicity, let's just return the candidateList stored in RAM instead of the file pointer
    return candidateLists, firstCandIndices

def test(cipherwords):
    Map = initMap()
    distinctCipherWords = searchReorder(list(set(cipherwords)))
    candidateLists, firstCandIndices = createCandidateLists(distinctCipherWords)
    Map = selfIntersection(Map, distinctCipherWords, candidateLists, firstCandIndices)
    
    
    # for P in candidates:
    #     print P

    # 
    # for P in candidates:
    #     print P
        
    # t = timeit.Timer(lambda: selfIntersection(Map, cipherwords))
    # print t.timeit(5)
    
    # def mycmp(x, y):
    #     if x not in asdf.keys():
    #         i = sys.maxint
    #     else:
    #         i = asdf[x]    
    #     
    #     if y not in asdf.keys():
    #         j = sys.maxint
    #     else:
    #         j = asdf[y]
    #     
    #     return i - j
    # 
    # f = open('words-sorted-by-pattern')
    # f2 = open('most-common-english-words.txt')
    # 
    # asdf = {}
    # for i, l in enumerate(f2):
    #     w = l[:-1]
    #     asdf[ w ] = i
    # 
    # f2.close()
    # 
    # w = f.readline()[:-1]
    # cur_P = getLetterPattern(w)
    # tmp = [w]
    # 
    # for l in f:
    #     w = l[:-1]
    #     next_P = getLetterPattern(w)
    #     if cur_P != next_P:
    #         tmp.sort(cmp=mycmp)            
    #         
    #         for t in tmp:
    #             print t
    #             
    #         cur_P = next_P
    #         tmp = [w]
    #     else:
    #         tmp.append(w)
    # 
    # for t in tmp:
    #     print t
    # 
    # f.close()
    
    
if __name__ == "__main__":
    if len(sys.argv) >= 3:
        f = open(sys.argv[1])
        cipherwords = []
        for line in f:
             cipherwords += line.split()
        f.close()
        
        # get cipherAlphabet - used in allCipherTextKnown() routine
        cipherAlphabet = ''.join(set(''.join(cipherwords)))
        
        f = open(sys.argv[2])
        
        unscramble(cipherwords)
        
        # test(cipherwords)
        f.close()
    else:
        print 'Usage: python unscramble.py <cipherwords> <dictionary>'