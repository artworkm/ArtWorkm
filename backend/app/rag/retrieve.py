
from qdrant_client.models import Filter, FieldCondition, MatchValue

from .embed import embed
from .store import get_client, COLLECTION


def search(
    query: str,
    k: int = 5,
    kind: str | None = None
) -> list[dict]:

    qvec = embed(
        [query],
        prefix="search_query: "
    )[0]

    flt = (
        Filter(
            must=[
                FieldCondition(
                    key="kind",
                    match=MatchValue(value=kind)
                )
            ]
        )
        if kind else None
    )

    res = get_client().query_points(
        COLLECTION,
        query=qvec,
        limit=k,
        query_filter=flt,
        with_payload=True
    )

    out = []

    for p in res.points:
        item = dict(p.payload)
        item["score"] = round(p.score, 4)
        out.append(item)

    return out
