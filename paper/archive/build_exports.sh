#!/usr/bin/env bash
#
# build_exports.sh -- regenerate the HTML/DOCX renderings of the two papers
# from their markdown sources, so the exports can never drift from the text.
#
#   paper/PAPER.md          -> paper/paper_humanized.html, paper/paper_humanized.docx
#   paper/manuscript_v2.md  -> paper/manuscript_v2.html,   paper/manuscript_v2.docx
#
# Needs pandoc (tested with 2.9.2.1). Run from anywhere:
#   ./paper/build_exports.sh
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

# The humanized HTML keeps its hand-written title block (everything up to the
# first <hr>) and takes the body from PAPER.md, starting at "## Abstract".
hdr=$(grep -n '^<hr>$' paper_humanized.html | head -1 | cut -d: -f1)
head -n "$hdr" paper_humanized.html > .hum_header.html
start=$(grep -n '^## Abstract' PAPER.md | cut -d: -f1)
{
    cat .hum_header.html
    echo
    tail -n +"$start" PAPER.md | pandoc -f gfm -t html
    printf '\n</body>\n</html>\n'
} > .paper_humanized.html
mv .paper_humanized.html paper_humanized.html
rm -f .hum_header.html
tail -n +"$start" PAPER.md | pandoc -f gfm -o paper_humanized.docx

pandoc manuscript_v2.md -f markdown-smart -s --self-contained \
    --metadata title="Passive detection of GTP-U tunnel abuse" -o manuscript_v2.html
pandoc manuscript_v2.md -f markdown-smart -o manuscript_v2.docx

echo "rebuilt paper_humanized.{html,docx} and manuscript_v2.{html,docx}"
