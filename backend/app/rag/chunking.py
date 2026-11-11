
def chunk_text(text: str, size: int = 1200, overlap: int = 150) -> list[str]:
    text = text.strip()

    if len(text) <= size:
        return [text] if text else []

    chunks, start = [], 0

    while start < len(text):
        end = min(start + size, len(text))

        # Prefer to cut at a paragraph or sentence.
        if end < len(text):
            cut = max(
                text.rfind("\n\n", start, end),
                text.rfind(". ", start, end)
            )

            if cut > start + size // 2:
                end = cut + 1

        piece = text[start:end].strip()

        if piece:
            chunks.append(piece)

        if end >= len(text):
            break

        # Overlap keeps context across chunk boundaries.
        start = max(end - overlap, start + 1)

    return chunks
