"""tokenizer_clip.py - CLIP BPE 分词器（openai/CLIP simple_tokenizer 的最小移植）

词表: bridge/bpe_simple_vocab_16e6.txt.gz（openai/CLIP 仓内文件，MIT 许可）。
仅依赖 regex + gzip；CLIP 约定：SOT(49406) + tokens(截断 75) + EOT(49407)，其余补 0。
"""
import gzip
import html
import os
import re
from functools import lru_cache

import regex


@lru_cache()
def bytes_to_unicode():
    bs = list(range(ord('!'), ord('~') + 1)) + list(range(ord('¡'), ord('¬') + 1)) + \
        list(range(ord('®'), ord('ÿ') + 1))
    cs = bs[:]
    n = 0
    for b in range(2 ** 8):
        if b not in bs:
            bs.append(b)
            cs.append(2 ** 8 + n)
            n += 1
    return dict(zip(bs, [chr(x) for x in cs]))


def get_pairs(word):
    pairs = set()
    prev = word[0]
    for ch in word[1:]:
        pairs.add((prev, ch))
        prev = ch
    return pairs


def basic_clean(text):
    return html.unescape(html.unescape(text.strip())).strip()


def whitespace_clean(text):
    return re.sub(r'\s+', ' ', text).strip()


class SimpleTokenizer:
    def __init__(self, bpe_path=None):
        bpe_path = bpe_path or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'bpe_simple_vocab_16e6.txt.gz')
        self.byte_encoder = bytes_to_unicode()
        merges = gzip.open(bpe_path, 'rt', encoding='utf-8').read().split('\n')
        merges = merges[1: 49152 - 256 - 2 + 1]
        merges = [tuple(m.split()) for m in merges if m.strip()]
        vocab = list(self.byte_encoder.values())
        vocab = vocab + [v + '</w>' for v in vocab]
        for merge in merges:
            vocab.append(''.join(merge))
        vocab.extend(['<start_of_text>', '<end_of_text>'])
        self.encoder = {t: i for i, t in enumerate(vocab)}
        self.bpe_ranks = dict(zip(merges, range(len(merges))))
        self.cache = {}
        self.pat = regex.compile(
            r"<\|startoftext\|>|<\|endoftext\|>|'s|'t|'re|'ve|'m|'ll|'d|"
            r"[\p{L}]+|[\p{N}]|[^\s\p{L}\p{N}]+", regex.IGNORECASE)

    def bpe(self, token):
        if token in self.cache:
            return self.cache[token]
        # openai 约定：结尾符 '</w>' 粘在最后一个字符上（'a' → 'a</w>'，基础词表即含）
        word = tuple(token[:-1]) + (token[-1] + '</w>',)
        if not word:
            word = ('</w>',)
        pairs = get_pairs(word)
        if not pairs:
            return token + '</w>'
        while True:
            bigram = min(pairs, key=lambda p: self.bpe_ranks.get(p, float('inf')))
            if bigram not in self.bpe_ranks:
                break
            first, second = bigram
            new_word = []
            i = 0
            while i < len(word):
                try:
                    j = word.index(first, i)
                except ValueError:
                    new_word.extend(word[i:])
                    break
                new_word.extend(word[i:j])
                i = j
                if word[i] == first and i < len(word) - 1 and word[i + 1] == second:
                    new_word.append(first + second)
                    i += 2
                else:
                    new_word.append(word[i])
                    i += 1
            word = tuple(new_word)
            if len(word) == 1:
                break
            pairs = get_pairs(word)
        out = ' '.join(word)
        self.cache[token] = out
        return out

    def encode(self, text):
        text = whitespace_clean(basic_clean(text)).lower()
        tokens = []
        for tok in self.pat.findall(text):
            tok = ''.join(self.byte_encoder[b] for b in tok.encode('utf-8'))
            tokens.extend(self.bpe(tok).split(' '))
        return tokens


def clip_tokenize(texts, context_length=77):
    """openai CLIP tokenize 约定 → (ids, attention_mask)，int64 [L, 77]"""
    import numpy as np
    if isinstance(texts, str):
        texts = [texts]
    tok = SimpleTokenizer()
    sot = tok.encoder['<start_of_text>']
    eot = tok.encoder['<end_of_text>']
    out = np.zeros((len(texts), context_length), dtype=np.int64)
    for i, text in enumerate(texts):
        bpe_tokens = tok.encode(text)[:context_length - 2]
        tokens = [sot] + [tok.encoder[t] for t in bpe_tokens] + [eot]
        out[i, :len(tokens)] = tokens
    return out, (out != 0).astype(np.int64)
