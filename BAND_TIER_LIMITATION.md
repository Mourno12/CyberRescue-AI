# Band Free Tier Limitation & Option B Workaround

**Date**: 2026-06-14  
**Finding**: Band's free tier blocks human API access (required for automatic room creation)

---

## The Issue

When testing Option B with a Band user API key, the injector received:

```
ForbiddenError: Human API access requires an Enterprise plan.
```

This applies to:
- `POST /me/chats` (create room)
- `POST /me/chats/{id}/participants` (add participant)
- `POST /me/chats/{id}/messages` (send message)

**All human-initiated room operations require Band Enterprise tier.**

---

## Impact on Option B

Option B's architecture is **still valid and works**:
- Triage agent can create rooms (agent API ✅, not blocked)
- Triage can add participants ✅
- Triage can post messages ✅

The **only** blocked piece is the injector's ability to automatically create an intake room via human API.

---

## Workaround: Manual Intake Room (For Demo/Testing)

### Step-by-Step

1. **Create intake room manually in Band UI**
   - Go to your Band account
   - Create a new chat room (call it "WarRoom Intake" or similar)
   - Note the room ID (visible in URL or room settings)

2. **Add Triage as participant**
   - In the room, use the "Add participant" feature
   - Select the Triage agent
   - Confirm

3. **Run the injector**
   ```bash
   python -m injector.inject_alert INC-C --dry-run
   ```
   (Or without --dry-run, it will auto-detect no manual setup and print the message)

4. **Copy the alert message**
   The injector prints a ready-to-paste alert like:
   ```
   @Triage *** NEW SECURITY ALERT *** INC-C-2026-0042
   Ransomware encryption activity on primary customer database
   ...
   ```

5. **Paste into the intake room**
   - In Band UI, go to the intake room
   - Paste the alert message
   - Hit send

6. **Triage reacts**
   - Triage reads the alert (it's @mentioned)
   - Classifies it via `classify_alert` tool
   - Creates the incident room via `thenvoi_create_chatroom`
   - Recruits specialists via `thenvoi_add_participant`
   - Posts the BRIEF

---

## Alternative: Use Dry-Run Output

For a quick demo without Band setup:

```bash
python -m injector.inject_alert INC-C --dry-run
```

This prints the alert message directly. You can then:
- Manually post it in any Band room with Triage
- Show the message structure for documentation
- Validate the alert format without needing network access

---

## Comparison: All Three Options

| Aspect | Option A | Option B (Current) | Option C |
|--------|----------|-------------------|----------|
| **Room created by** | Injector (human API) | Triage (agent API) | Pre-made |
| **Free tier friendly** | ❌ (needs human API) | ✅ (agent API only) | ✅ |
| **Demo narrative** | "Alert lands → room exists with team" | "Alert → Triage spins up room → recruits" | "Room pre-made" |
| **Real-world alignment** | Agent-agnostic | Best (Triage owns incident) | Wasteful |
| **Current testing path** | ❌ Blocked | ✅ Manual workaround | ✅ Pre-made |

**Conclusion**: Option B is **the right long-term choice** but requires:
- Manual intake room setup for free-tier demos, OR
- Band Enterprise tier for full automation

---

## For Phase 5 (Human-in-the-Loop)

The CISO can be added to the incident room in two ways:

1. **Triage adds them** (Option B as designed)
   - Works if Triage has `add_participant` for humans
   - Phase 0 verified this works ✅

2. **CISO pre-joins intake room, then moves to incident room**
   - CISO manually joins the intake room
   - Sees Triage activity
   - Is automatically added to incident room when Triage creates it (or is @mentioned)

---

## Testing Checklist

- [ ] Create intake room manually in Band UI
- [ ] Add Triage agent as participant
- [ ] Run `python -m injector.inject_alert INC-C --dry-run` to get the message
- [ ] Paste alert into intake room
- [ ] Observe Triage reading alert (should see it in Triage's logs)
- [ ] Observe Triage creating incident room
- [ ] Verify incident room has Triage + CISO + recruited specialists
- [ ] Verify BRIEF message mentions everyone
- [ ] Run INC-A (no escalation) and INC-B (close at triage)

---

## Next Steps

1. **For immediate demo**: Use manual intake room + dry-run workaround
2. **For full automation**: Band Enterprise tier required (or use Option A/C)
3. **For long-term production**: Option B architecture is correct; use Band Enterprise or self-host/proxy the API

The code is correct; it's just a Band platform tier limitation.
