# ADR-017: Desktop-First UI, Mobile via Bot

**Date:** April 2026
**Status:** Accepted

**Decision:** The dashboard is desktop-first and mobile-responsive. Investigation and configuration require a desktop. Mobile interaction happens via Discord/Slack/Telegram bots, not via mobile app or mobile-optimized UI.

**Alternatives considered:**
- Native mobile app — rejected. Doubles maintenance for solo development; investigation work cannot be meaningfully done on a phone screen.
- Mobile-first responsive design — rejected. Compromises desktop UX (the primary surface) for a use case that's better solved by bots.
- Desktop-only, no mobile responsiveness at all — rejected. Mobile-responsive comes essentially free with modern frameworks; breaking mobile would frustrate users who get a Discord alert and want to peek before they get to a desk.

**Reasoning:** The daily SOC workflow has two phone moments: receiving alerts (already solved by webhooks) and acknowledging or taking quick action on those alerts (solved by chat bots that can reply with `/block <ip>` or `/ack <id>`). Neither needs a custom mobile UI. Building a mobile UI doubles the surface area while making the desktop experience worse.

**Bot capabilities to implement (after Active Response ships):**
- Receive alerts (already done)
- `/block <ip> [duration]` — apply a block from chat
- `/ack <alert_id>` — mark an alert as acknowledged
- `/details <ip>` — get AI summary inline in chat
- `/snooze <rule_id> <duration>` — suppress noisy rule temporarily
