from __future__ import (
    absolute_import,
    division,
    print_function,
)

import re

from scrapy.selector import Selector

RE_FOR_THE = re.compile(
    r'\b(?:for|on behalf of|representing)\b',
    re.IGNORECASE,
)
INST_PHRASES = ['for the development', ]


def get_node(text, namespaces=None):
    """Get a scrapy selector for the given text node."""
    node = Selector(text=text, type="xml")
    if namespaces:
        for ns in namespaces:
            node.register_namespace(ns[0], ns[1])
    return node


def coll_cleanforthe(coll):
    """ Cleanup collaboration, try to find author """
    author = None

    if any(phrase for phrase in INST_PHRASES if phrase in coll.lower()):
        # don't touch it, doesn't look like a collaboration
        return coll, author

    coll = coll.strip('.; ')

    if RE_FOR_THE.search(coll):
        # get strings leading and trailing 'for the'
        (lead, trail) = RE_FOR_THE.split(coll, maxsplit=1)
        if re.search(r'\w', lead):
            author = lead.strip()
        if re.search(r'\w', trail):
            coll = trail

    coll = re.sub('(?i)^ *the ', '', coll)
    coll = re.sub('(?i) *collaborations? *', '', coll)
    coll = coll.strip()

    return coll, author


def split_fullname(author, switch_name_order=False):
    """Split an author name to surname and given names.

    It accepts author strings with and without comma separation.
    As default surname is first in case of comma separation, otherwise last.
    Multi-part surnames are incorrectly detected in strings without comma
    separation.
    """
    if not author:
        return "", ""

    if "," in author:
        fullname = [n.strip() for n in author.split(',')]
        surname_first = True
    else:
        fullname = [n.strip() for n in author.split()]
        surname_first = False

    if switch_name_order:
        surname_first = not surname_first

    if surname_first:
        surname = fullname[0]
        given_names = " ".join(fullname[1:])
    else:
        surname = fullname[-1]
        given_names = " ".join(fullname[:-1])

    return surname, given_names


CONFERENCE_WORDS = [
    'colloquium',
    'colloquiums',
    'conf',
    'conference',
    'conferences',
    'contrib',
    'contributed',
    'contribution',
    'contributions',
    'forum',
    'lecture',
    'lectures',
    'meeting',
    'meetings',
    'pres',
    'presented',
    'proc',
    'proceeding',
    'proceedings',
    'rencontre',
    'rencontres',
    'school',
    'schools',
    'seminar',
    'seminars',
    'symp',
    'symposium',
    'symposiums',
    'talk',
    'talks',
    'workshop',
    'workshops'
]

THESIS_WORDS = [
    'diploma',
    'diplomarbeit',
    'diplome',
    'dissertation',
    'doctoraal',
    'doctoral',
    'doctorat',
    'doctorate',
    'doktorarbeit',
    'dottorato',
    'habilitationsschrift',
    'hochschule',
    'inauguraldissertation',
    'memoire',
    'phd',
    'proefschrift',
    'schlussbericht',
    'staatsexamensarbeit',
    'tesi',
    'thesis',
    'travail'
]
