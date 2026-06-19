# FIXTURE (vulnerable by design, polyglot). Framework auto-serializer egress:
# Django returns a deck as JSON with no authorization on the resolved object.
from django.http import JsonResponse, StreamingHttpResponse


def deck_json(request, deck_id):
    deck = Deck.objects.get(pk=deck_id)  # no owner/tenant/verification scope
    return JsonResponse({"id": deck.id, "content": deck.content})


def deck_stream(request, deck_id):
    return StreamingHttpResponse(stream_deck(deck_id))
