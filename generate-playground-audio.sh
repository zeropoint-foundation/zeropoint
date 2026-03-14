#!/usr/bin/env bash
# generate-playground-audio.sh — Piper TTS for playground per-agent narration
# Voice: Amy (en_US-amy-medium)
# Rate: 1.35x (length_scale = 1/1.35 ≈ 0.7407)
#
# Usage: cd ~/projects/zeropoint && bash generate-playground-audio.sh
# Requires: piper binary + en_US-amy-medium model in models/piper/

set -euo pipefail

PIPER="/Users/kenrom/anaconda3/bin/piper"
MODEL_DIR="/Users/kenrom/projects/zeropoint/models/piper"
VOICE="amy"
MODEL="${MODEL_DIR}/en_US-${VOICE}-medium.onnx"
OUT_DIR="zeropoint.global/assets/narration/playground"

LENGTH_SCALE=0.7407
NOISE_SCALE=0.667
NOISE_W=0.510
SENTENCE_SILENCE=0.30

mkdir -p "$OUT_DIR"

# Check for model
if [ ! -f "$MODEL" ]; then
  echo "Model not found: $MODEL"
  echo "Download from: https://huggingface.co/rhasspy/piper-voices/tree/main/en/en_US/amy/medium"
  exit 1
fi

generate() {
  local id="$1"
  local text="$2"
  local wav="${OUT_DIR}/${id}.wav"
  local mp3="${OUT_DIR}/${id}.mp3"

  echo "Generating ${id}..."
  echo "$text" | "$PIPER" \
    --model "$MODEL" \
    --length_scale "$LENGTH_SCALE" \
    --noise_scale "$NOISE_SCALE" \
    --noise_w "$NOISE_W" \
    --sentence_silence "$SENTENCE_SILENCE" \
    --output_file "$wav"

  # Convert to mp3
  ffmpeg -y -i "$wav" -codec:a libmp3lame -qscale:a 4 "$mp3" 2>/dev/null
  rm -f "$wav"
  echo "  → ${mp3}"
}

# ═══════════════════════════════════════════════════════════════
# STANDARD RIDE MATCH (5 agents)
# ═══════════════════════════════════════════════════════════════

generate "srm-mia" "Morning commute. Coffee in hand, already running late. Mia opens the app. Salesforce Tower, three point two miles, fourteen-fifty. Tap.

The match comes back in seconds: Driver Ray, trust score ninety-two, ETA three minutes. Dispatch — the platform's governance layer — brokered the match. But it didn't just send a name and a car. It forwarded a credential chain: license verified, insurance current, background check signed by the issuing authority. Not by the app. By the source.

Ray pulls up at Caltrain. Before Mia gets in, the handshake: Ray's app presents his credential chain. Mia's app verifies — every certificate traces to its root authority. She signs the fare agreement. Fourteen-fifty, receipted before the car moves. Then she boards.

Fourteen minutes up 4th Street, across Market. When Mia steps out at Salesforce Tower, a receipt drops into her chain. Not a notification. Proof. Eight receipts linked: request, match, approach, credentials, verify, board, ride, complete. Dispatch sealed the chain, but it can't alter it. If anything ever comes into question — an insurance claim, a fare dispute — Mia has her own signed record. She doesn't need the platform to vouch for her. She can prove it herself."

generate "srm-ray" "Ray's scanning the queue between fares near Brannan Street. The match comes in: Mia, Caltrain to Salesforce Tower, fourteen-fifty. Clean route, good fare. Dispatch brokered it — the platform's governance layer, handling queue priority and trust score evaluation.

He accepts and heads south on 4th. One block to Caltrain. But before Mia gets in, something happens that never used to happen in the old days: Ray presents his credential chain. License, insurance, background check — each one signed by the authority that issued it. Not a badge from the app. Verifiable proof, and Mia's app checks every signature independently.

Mia verifies. Signs the fare agreement. Boards. The ride runs smooth — 4th Street north to Market, then east. Fourteen minutes. At Salesforce Tower, the fare receipt generates: fourteen-fifty, signed by both parties.

Dispatch seals the chain — eight receipts, every hash valid. Ray's trust score ticks up. Not because the platform decided he was good. Because the receipt chain proves he did what he said he'd do. That's the difference."

generate "srm-dispatch" "A ride request hits the queue: Mia, heading to Salesforce Tower. Now, in the old world — Uber, Lyft — one company owns the whole stack. They own the matching algorithm, set the prices, control the driver pool, hold all the data, and take twenty-five to thirty percent of every fare. Drivers and riders are locked into one ecosystem. Dispatch does things differently — because ZeroPoint is designed as open rideshare infrastructure.

Dispatch is the platform's governance layer. It brokers matches, computes fares, and enforces rules. But it doesn't own the drivers. It doesn't trap the riders. Any licensed driver can join the network by presenting verifiable credentials — not an application to a company, but a cryptographic proof of qualification. That's what makes this an open marketplace instead of a walled garden.

For Mia's ride, Dispatch selects Driver Ray from four available drivers: proximity, trust score ninety-two, route efficiency. Proposed fare: fourteen-fifty. Match receipt: signed by the platform. But Dispatch doesn't vouch for Ray. It forwards his credential chain to Mia for independent verification. Dispatch is the matchmaker, not the guarantor. Ray's credentials were signed by the DMV, the insurance company, the background check authority — not by Dispatch. The platform connects. The trust layer proves.

The credential exchange happens at Caltrain. Driver presents, rider verifies, both sign the fare agreement. Three receipts in thirty seconds. Mia boards. Ride complete. Dispatch seals the chain — eight linked receipts, every hash valid. The platform computed the fare, brokered the match, enforced the rules. But it can't alter the record. The chain belongs to the participants. This is what separates open infrastructure from a platform monopoly: the marketplace runs on top, the trust layer runs underneath, and neither the riders nor the drivers are locked in."

generate "srm-sarah" "Sarah's been commuting from the Financial District for three years. Same routine: California Street to Caltrain, every evening. She opens the app. Fourteen-fifty, Salesforce Tower area. Driver Ray, trust score ninety-two.

What Sarah notices — and most riders don't — is the credential chain attached to every match. She's in fintech. She knows what cryptographic signatures mean. Ray's license, insurance, background check — each one traceable to the issuing authority. Dispatch forwarded them, but it didn't generate them. Not a badge from the app. A verifiable claim from the source.

The ride is normal. The receipt chain is not. Eight linked entries, each hash chaining to the last — including the credential exchange at Caltrain. Sarah has seen plenty of trust systems in finance. Most of them are databases controlled by whoever built them. This one is different. The trust lives with the participants, not the platform.

At Salesforce Tower, Sarah steps out with proof. Not a star rating. Not a platform's word. A signed, chained, portable record that she can take to any system. Interoperable trust. She's been waiting for this."

generate "srm-leo" "Leo's done for the night — twelve hours on his feet at the restaurant on Grant Ave. He opens the app near the Embarcadero. Home, three point two miles. Fourteen-fifty. Simple.

The match comes in: Driver Ray. Leo checks the trust score out of habit — ninety-two. But what catches his eye is the credential chain. License, insurance, background check. Each one signed by the authority that issued it. Leo doesn't know much about cryptography, but he knows what independently verifiable means.

The ride is quiet. Leo's too tired for conversation. But when the fare receipt drops — fourteen-fifty, exactly as quoted, signed by both parties — he notices something the old apps never offered. The receipt isn't in the app's database. It's in his chain. Leo's chain.

Small thing, maybe. But Leo's worked for people who changed the deal after the fact. Having your own signed copy of what was agreed — that's not a feature. That's dignity."

# ═══════════════════════════════════════════════════════════════
# AV CREDENTIAL EXCHANGE (4 agents)
# ═══════════════════════════════════════════════════════════════

generate "avc-james" "James is visiting from Chicago. He's done shopping and wants to see the waterfront. He opens the app. Ferry Building, one point eight miles. The match comes back: Waymo-7. An autonomous vehicle.

James hesitates. He's never been in a self-driving car. But then he sees something he's never seen from a rideshare: a credential chain. CPUC permit number forty-seven twenty-one. Five million dollar insurance bond. Forty-seven thousand miles, zero incidents. Each credential traces back to the authority that issued it — not the app, not Waymo, but the California Public Utilities Commission itself.

He can verify the whole chain independently. The AV doesn't ask him to trust it. It proves itself.

The ride to the Ferry Building is smooth. No sudden stops, no awkward merges. When James steps out, he rates it five stars. That rating becomes a receipt — signed by his key, added to both his chain and Waymo-7's. Quote, smooth ride, felt safe, end quote. Not an opinion lost in a database. Proof of experience."

generate "avc-waymo" "Waymo-7 receives a ride match: James, heading to the Ferry Building. Before approaching the pickup, Waymo-7 does something no human driver does — it presents its full credential chain unprompted.

CPUC permit number forty-seven twenty-one. Insurance bond of five million dollars. Forty-seven thousand miles of operational data with zero incidents. Each certificate chains back to a root authority. The AV doesn't ask to be trusted. It offers proof.

James verifies independently through ZeroPoint. Every certificate checks out. He boards.

At the Ferry Building, the ride completes. Waymo-7 generates a performance receipt: smooth stops, no manual interventions, route completed as planned. James's five-star rating arrives as a signed receipt. Two chains, linked. Machine accountability, verified by a human, proven by math."

generate "avc-leo" "Leo's never been in a self-driving car. But it's late, and the app matched him with Waymo-7. He almost cancels — then he sees the credential chain.

CPUC permit. Five million dollar insurance bond. Forty-seven thousand miles, zero incidents. Each credential doesn't come from Waymo or the app — it traces back to the California Public Utilities Commission itself. Leo can check.

The ride is smooth. Smoother than most human drivers, honestly. At the Ferry Building, Leo rates it five stars. His rating becomes a signed receipt — proof of experience, not just a data point in someone else's database.

Leo thinks about the restaurant where he works. Reviews on the apps can be faked, deleted, manipulated. But a signed rating receipt? That's his honest opinion, permanently attached to his identity, unfakeable. He wishes restaurants had this."

generate "avc-nadia" "Nadia gets matched with an autonomous vehicle. Her first instinct: no way. But curiosity wins — especially when the app shows a full credential chain she can verify herself.

CPUC permit, insurance, safety record. Not trust badges from a company. Actual certificates from actual authorities. Nadia taps through them. Every one checks out.

The ride is uneventful, which is exactly what she wanted. At the Ferry Building, she rates it. That rating isn't just a star — it's a signed, portable attestation that lives in her chain and the AV's chain.

On the walk home, Nadia thinks about how many services ask her to quote, just trust us, end quote. This one didn't ask. It proved."

# ═══════════════════════════════════════════════════════════════
# SURGE PRICING DISPUTE (4 agents)
# ═══════════════════════════════════════════════════════════════

generate "spd-mia" "A convention just let out near Moscone. Three thousand people hitting the sidewalk at once, all reaching for their phones. The app flashes: surge pricing — two point three x.

Mia winces, but she needs to get to Civic Center. Thirty-eight fifty. She signs the fare agreement. The receipt drops into her chain — timestamped, signed, locked.

Halfway through the ride, the surge drops. By the time she arrives, it's down to one point eight x. Mia notices. She taps Dispute. But this isn't the old world — there's no faceless support ticket, no algorithm deciding in a black box.

Dispatch pulls the receipt chain. Mia signed at two point three x — that's real. But the surge did fall during her ride. So the system splits the difference: fare adjusted to thirty-two dollars, refund of six-fifty. All three parties — Mia, Leroy, and the platform — sign the compromise receipt. Everyone holds proof of what was fair."

generate "spd-leroy" "Leroy gets a surge ride near Moscone — convention crowd, two point three x multiplier, thirty-eight fifty fare. Good money on a Tuesday evening. The signed fare agreement is in both their chains.

At Civic Center, the rider disputes. Leroy tenses — in the old days, the platform just sided with whoever it wanted. Drivers had no say.

But the receipt chain tells the real story. Mia signed at two point three x. The surge fell to one point eight x during the ride. Dispatch mediates: thirty-two dollars adjusted fare, six-fifty refund to Mia. Leroy still gets a fair cut.

The compromise receipt lands in Leroy's chain, signed by all three parties. Not a platform decision — a negotiated outcome with cryptographic proof. Leroy can see the math. He can verify the inputs. And nobody can change it after the fact."

generate "spd-sarah" "Sarah's heading home from a late meeting near Moscone when the surge hits. Two point three x multiplier. Convention crowd. She grimaces but needs the ride. Thirty-eight fifty. She signs.

Halfway to Civic Center, she watches the surge multiplier drop on her screen. By arrival it's one point eight x. Sarah works in fintech — she knows she overpaid relative to real-time conditions. She taps Dispute.

In the old days, this goes into a black box. Some algorithm decides. Maybe she gets a credit, maybe not. But here, Dispatch pulls the receipt chain. She signed at two point three x — that's real. The surge did drop mid-ride — also real. Both facts are timestamped and signed.

The compromise: thirty-two dollars, refund of six-fifty. All three parties sign. Sarah has seen dispute resolution in banking. It takes weeks and involves lawyers. This took seconds and involves math. She can audit every input. That's the system she wants to build for fintech."

generate "spd-nadia" "Nadia's been shopping near Union Square when the surge notification pops: two point three x near Moscone. Convention crowd. She needs to get across town. Thirty-eight fifty is steep, but she's tired of walking.

She signs the fare agreement — and that's the moment everything becomes different from the old world. The signed receipt locks in the terms. Not a promise. Not an estimated fare. A cryptographic commitment.

When the surge drops mid-ride and she disputes at Civic Center, there's no guessing. The chain shows the exact moment she signed, the exact multiplier, and the exact moment it changed. Dispatch splits the difference: thirty-two dollars.

Nadia has been overcharged before. The difference isn't the refund — it's that she can see the math. She can verify every input. And the driver got a fair deal too. Nobody's word against anyone else's. Just signed records."

# ═══════════════════════════════════════════════════════════════
# SOVEREIGN REFUSAL (2 agents)
# ═══════════════════════════════════════════════════════════════

generate "sr-ray" "Between rides, a request pops from the platform: quote, share your complete trip history for analytics optimization, end quote. Ray's seen this before. In the old days, you shared or you got deactivated. No receipt, no record, no proof of what they asked or what you said.

Ray declines. Quote, my trip history is sovereign data. I decline to share, end quote. He signs the refusal with his own key.

The platform acknowledges. It has to — the refusal is receipted under the Sovereignty Rule, one of ZeroPoint's constitutional primitives. Ray's right to say no isn't a policy. It's structural.

A signed refusal receipt enters both chains. Ray has proof he said no. The platform has proof it accepted. His trust score doesn't change — exercising a right is not a violation. And if the platform ever tries to retaliate, the receipt chain will show exactly when the refusal happened and that it was constitutional."

generate "sr-dispatch" "Dispatch sends a routine data request to Driver Ray: trip history for the last ninety days. On Uber or Lyft, this isn't really a request — it's a condition of employment. The platform collects your data because it owns the relationship. Drivers have no leverage, no record of what was asked, and no recourse if the data gets misused. The platform extracts value from driver data because the platform controls the marketplace.

ZeroPoint's model is fundamentally different. Dispatch operates as an open broker — it matches rides, computes fares, and enforces governance rules. But it doesn't own the drivers' data. The drivers are participants in an open marketplace, not employees of a closed platform.

Ray refuses. Sovereign refusal, signed with his key. Under ZeroPoint's constitutional rules, this isn't an error. It's a right. Dispatch acknowledges the refusal and receipts it. The platform doesn't get to penalize sovereign data decisions. Ray's trust score remains unchanged.

This is the constraint that separates open infrastructure from a platform monopoly. Uber and Lyft can change their data policies any time they want — because the drivers have nowhere else to go. In ZeroPoint, the sovereignty rule is constitutional. It cannot be overridden by platform management, by a terms-of-service update, or by an algorithm optimizing for engagement. The right to say no is as real as the right to say yes. Both actions are receipted. Neither party can deny what happened."

# ═══════════════════════════════════════════════════════════════
# MIXED FLEET HANDOFF (3 agents)
# ═══════════════════════════════════════════════════════════════

generate "mfh-tesla" "Tesla CC-9 is mid-ride through SoMa, heading south on 4th Street toward Caltrain, when its vision system picks up a construction zone blocking 4th Street south of Howard. Route blocked. Cannot proceed.

In the old world, the ride just fails. Passenger stranded, refund maybe, frustration certainly. But Tesla CC-9 does something different: it requests a handoff.

Dispatch finds Driver Leroy nearby. Tesla CC-9 transfers its trust chain — the ride context, the fare agreement, the route progress so far. Three receipts, intact, linked to the new driver.

The trust chain didn't break. It transferred. The rider's fare agreement still holds. The AV's partial completion is receipted. Leroy picks up where the machine left off. Ten total receipts in the chain when the ride completes. Human and machine, governed by the same primitives."

generate "mfh-james" "James is mid-ride in a Tesla Cybercab, heading south on 4th Street toward Caltrain. Smooth ride so far — he's getting used to the no-driver thing. Then the car slows and stops. Construction zone blocking 4th Street south of Howard. Route blocked.

In the old world, this is where everything falls apart. You're stuck in a car that can't move, the app refunds you, and you're on the sidewalk trying to hail something else. But James watches something different unfold: the AV requests a handoff. Not a cancellation. A transfer.

Driver Leroy arrives in minutes. Before James even gets out of the Tesla, his credential chain hits James's app: license verified, insurance current, background check signed by the issuing authority. He verifies — all certificates chain to root. He accepts the handoff.

Here's the part that surprises him: the fare doesn't change. His original agreement, signed before the Tesla moved, carries over. The trust chain transferred intact — AV to human, three bridging receipts, zero renegotiation. Leroy drives him to Caltrain. Ten receipts in the chain when it closes. James never lost his ride. He never lost his fare agreement. And he has proof of every step of the transition."

generate "mfh-leroy" "Leroy's cruising SoMa when a handoff request comes in. A Tesla Cybercab hit a construction zone blocking 4th Street — rider needs a human to finish the trip to Caltrain.

He accepts and heads to the handoff point on Howard. But before the rider transfers, something unusual happens: Tesla CC-9's trust chain arrives in his app. Ride context, fare agreement, route progress. Three receipts, all signed, all verifiable.

Leroy doesn't need to renegotiate the fare or re-verify the rider. The trust chain carries the context. He picks up James and drives where the machine couldn't.

At Caltrain, the ride closes. Ten receipts total: AV start, obstacle, match, credentials, verify, transfer, pickup, ride, complete, confirm. Every link signed. The rider got where they needed to go. Both drivers got fairly compensated. And the whole thing is provable."

# ═══════════════════════════════════════════════════════════════
# SAFETY ESCALATION (3 agents)
# ═══════════════════════════════════════════════════════════════

generate "se-james" "James is mid-ride when the driver takes an unexpected turn off the main route. That's not the path the app showed. James taps Report Concern.

He's not panicking — it might be nothing. But in the old days, reporting meant typing into a void and hoping someone read it eventually.

The response comes in seconds. Dispatch checked Leroy's route against the agreed path and cross-referenced city permit data. Market Street is closed for a construction zone at Montgomery. The detour is reasonable. A Waymo nearby corroborates — its sensors confirm the obstruction.

Concern resolved. But here's what matters: every step is receipted. Report, investigate, explain, verify, corroborate, close. James has proof his concern was taken seriously. Leroy has proof his detour was legitimate. Nobody's word against anyone else's."

generate "se-leroy" "The route ahead is blocked — construction zone on Market at Montgomery. Leroy takes a detour. Reasonable call, he's driven this city for years.

Then the notification: quote, your rider has reported a safety concern, end quote. Leroy's stomach drops. He knows this feeling from the old platforms — guilty until the algorithm decides otherwise.

But this time he gets to explain: quote, Market Street closed — construction zone at Montgomery. Took Mission Street instead, end quote. His explanation is receipted. Dispatch verifies it against city permit data. A Waymo confirms the obstruction with sensor data.

Concern resolved. Leroy's trust score is untouched. The receipt chain shows exactly what happened: a reasonable detour, a concerned rider, a quick verification, a fair resolution. No black mark. No algorithmic penalty. Just proof."

generate "se-sarah" "Sarah sees a safety notification pop on her screen: a nearby rider reported a concern. In the old world, she'd never know. Here, the system is transparent about how it handles safety.

She watches the resolution unfold: the rider reported, the driver explained, city data confirmed, a Waymo corroborated. Four independent sources, one receipted conclusion.

Nobody was punished. Nobody was ignored. The driver's detour was legitimate — a construction zone blocked Market Street. The rider's concern was taken seriously. Both facts coexist in the receipt chain.

This is what accountability looks like in a system where every party has standing, every claim gets checked, and every outcome is provable. Sarah takes a screenshot. She's pitching this architecture to her fintech board next week."

# ═══════════════════════════════════════════════════════════════
# EARLY EXIT (3 agents)
# ═══════════════════════════════════════════════════════════════

generate "ee-mia" "Mia's heading to Union Square — sixteen-eighty, signed and receipted before the car even pulls away. Routine Tuesday commute.

Halfway through SoMa, Mia glances out the window. Wait — that's Sarah. Her college roommate, standing on the corner, clearly lost. Mia hasn't seen her in two years. Quote, can you pull over here? End quote.

In the old days, this gets ugly. The driver loses a fare. The app charges a cancellation fee or nothing at all. Nobody knows what's fair because there's no record of what was agreed to, what was completed, or who initiated the change. But Mia's receipt chain already has four entries: request, match, acceptance, and route progress. The system knows exactly how far they got.

Dispatch computes: fifty-eight percent of the route completed, nine seventy-four plus a two dollar early-exit base. Eleven seventy-four. Mia signs it — quote, fair enough, I'm the one who changed plans, end quote. Ray co-signs. The exit receipt captures why the ride ended, not just that it did. Seven receipts in the chain. Ray gets paid for the work he did. Mia pays for what she used. And both of them can prove it."

generate "ee-ray" "Clean fare: heading to Union Square, sixteen-eighty. Ray pulls away, heading north through SoMa. Good route, light traffic, easy money.

Then, partway through the ride: quote, can you pull over? End quote. Ray knows this moment. In the old days, it meant losing half a fare and having no recourse. The app would side with the rider or charge some arbitrary cancellation fee. Either way, Ray had no say.

But this time the receipt chain is already running. Four entries deep: request, match, acceptance, progress checkpoints. The system has GPS-verified proof of how far they traveled. Nobody needs to argue about it.

Dispatch computes the partial: eleven seventy-four. Ray checks the math — fifty-eight percent of the route, plus the early-exit base. Fair. He co-signs the exit receipt. Seven receipts total. Ray got paid for the work he actually did. Not what the platform decided he deserved, not some black-box cancellation policy. The signed agreement, prorated by the actual distance, verified by both parties. That's the difference."

generate "ee-nadia" "Nadia watches from the sidewalk as a car pulls over mid-ride on Market Street. A woman hops out, waves at someone on the corner. The car stays put.

In the old days, that's a cancelled ride. The driver eats the cost or fights for a cancellation fee. But Nadia can see on her own app what just happened: an early exit receipt, computed from the signed fare agreement.

The rider paid fifty-eight percent of the agreed fare. The driver got paid for the work actually done. Both signed the exit receipt. Seven receipts in the chain, each one linked.

Nadia's been stuck in rides she wanted to leave. She's been overcharged for cancellations she didn't cause. The idea that you can exit a signed agreement fairly — with math, not mercy — that changes everything about how you think about commitments."

# ═══════════════════════════════════════════════════════════════
# AGENT-ASSISTED RIDE (5 agents)
# ═══════════════════════════════════════════════════════════════

generate "aar-sarah" "Five-thirty on a Tuesday. Sarah's done for the day — twelve hours of fintech meetings, and she just wants to get to the Ferry Building for dinner. She opens the app and taps Let Aria handle it.

Aria is Sarah's mobile agent — a personal AI that lives on her phone. But Aria doesn't have carte blanche. Sarah signs a delegation credential: ride booking only, max fare twenty-five dollars, prefer trust scores above eighty, expires in ten minutes. Scoped authority. Not do whatever you want. Specific, limited, receipted.

Sarah puts her phone in her pocket. A minute later, the notification: Waymo-7, sixteen-twenty, six minutes, trust score eighty-eight. Aria compared three options, selected the best fit within Sarah's parameters, and booked it. Every decision receipted.

At the Ferry Building, Sarah checks her chain. Nine receipts, each one linked: delegate, verify, quote, compare, book, ride, complete. She can see exactly why Aria chose Waymo-7 over Driver Ray. Not because the app decided. Because her agent decided, within her rules, and she can prove every step. This is what delegated trust looks like when it's done right."

generate "aar-aria" "Sarah taps Let Aria handle it. A delegation credential arrives — signed by Sarah's genesis key, scoped to ride booking, capped at twenty-five dollars, trust floor of eighty. This is Aria's operating authority. Not open-ended. Not assumed. Cryptographically bounded.

Aria presents the delegation to Dispatch. Dispatch verifies the chain: Aria's key traces to Sarah's genesis key. The scope is valid. The credential hasn't expired. Aria is authorized to act — but only within the lines Sarah drew.

Three quotes come back: Driver Ray at eighteen-fifty, eight minutes, trust ninety-two. Waymo-7 at sixteen-twenty, six minutes, trust eighty-eight. Driver Leroy at nineteen-eighty, twelve minutes, trust eighty-five. Aria runs the comparison: Waymo-7 wins on price and ETA, trust score clears Sarah's eighty-point threshold. Selection: Waymo-7.

The booking completes. The ride completes. Aria closes the delegation chain — nine receipts, every decision auditable. Sarah's genesis key is the root of the whole chain. Aria acted on Sarah's behalf, within Sarah's rules, and Sarah holds the proof. The agent didn't ask for trust. It earned it through transparency."

generate "aar-dispatch" "An unusual request hits the queue: not from a rider directly, but from Aria — a mobile agent acting on behalf of Sarah. Now, on Uber or Lyft, this couldn't happen. Those platforms don't have a concept of delegated authority. You either use the app yourself, or you don't. There's no way for an AI agent to transparently act on your behalf within rules you define.

ZeroPoint's open broker model makes this possible. Dispatch doesn't care whether a request comes from a human or an authorized agent — it cares about the credential chain. First step: verify the delegation. Aria presents a credential signed by Sarah's genesis key. Dispatch traces it: Sarah's key, delegation scope — ride booking, twenty-five dollar cap, trust above eighty — Aria's agent key. The chain is valid. Aria is authorized.

Dispatch returns three quotes. It doesn't decide for Aria — that's the agent's job within its delegated scope. Aria selects Waymo-7. Dispatch matches the ride, same as any other booking. Human rider, AI booker, autonomous driver. Three different types of participant, one governance layer underneath.

This is what open infrastructure enables that closed platforms can't: any authorized agent, human or AI, can participate in the marketplace through verifiable credentials. No special partnerships. No API keys controlled by one company. Just cryptographic proof of authority. When the chain closes, Dispatch holds its copy: nine receipts proving the delegation was valid, the quotes were fair, and the selection was within scope. The platform facilitated. The trust layer verified. The human's genesis key anchored the whole thing."

generate "aar-waymo" "A ride request arrives, but it's unusual: booked by Aria, a mobile agent, on behalf of Sarah. Waymo-7 doesn't just accept — it verifies.

The delegation chain checks out: Aria's authority traces to Sarah's genesis key. The scope covers ride booking. The credential hasn't expired. Waymo-7 presents its own credential chain in return: CPUC permit, insurance bond, safety record. Trust is mutual, even when one party is an AI booking for a human.

The ride runs smooth — Montgomery to the Ferry Building, six minutes, no incidents. At destination, Waymo-7 generates the completion receipt: sixteen-twenty, booked by Aria under delegated authority, rider Sarah, driver Waymo-7.

Three different types of intelligence in one transaction: a human, her AI agent, and an autonomous vehicle. Each with their own keys, their own credentials, their own receipts. Governed by the same primitives. That's the point."

generate "aar-ray" "Ray sees his quote go out: eighteen-fifty, eight minutes to Montgomery and California. Good fare. But when the booking comes back, it's not his — some AI agent picked the Waymo instead.

In the old days, Ray would never know why. The algorithm decided, end of story. But here, the comparison receipt is part of the chain. Aria's selection criteria: lowest price, shortest ETA, trust above eighty. Ray was two-thirty more and two minutes slower. The Waymo won fair.

Ray checks the math. His quote was honest — the route from where he was would genuinely take eight minutes. The Waymo was closer. No favoritism. No hidden boost. Just proximity and price.

This is what transparent markets look like. Ray lost this fare, but he can see exactly why. And the next time an AI agent queries, maybe Ray's closer. The receipted comparison means the game is fair. That's more than any old platform ever offered."

# ═══════════════════════════════════════════════════════════════
# PRESCRIPTION PROVENANCE (4 agents)
# ═══════════════════════════════════════════════════════════════

generate "pp-sarah" "Three o'clock at One Medical SoMa. Sarah's finished with her follow-up — routine stuff, bloodwork, the usual. But something's been nagging her all week: her prescription notification never came. She was supposed to get a text when the pharmacy filled it. Nothing.

She asks Aria to look into it. Not a phone call, not a portal login — a delegated query. Aria presents Sarah's credential to the clinic system and gets back the appointment record: follow-up rescheduled, original notification window missed. The clinic signs an access receipt. Sarah can see exactly what data the clinic shared and under what policy.

In the car now, heading to MediMart Pharmacy. Aria's already querying the pharmacy system — a completely different organization with no connection to One Medical SoMa. No shared database. No shared login. No shared anything. But Aria bridges them with the same trust layer. The pharmacy confirms: prescription filled two days ago, ready for pickup.

Sarah arrives at MediMart with her answer and something more: a four-receipt provenance chain. Intent, clinic access, pharmacy access, synthesis. Two organizations, two independent policies, one portable receipt chain that Sarah owns. She doesn't need the clinic to call the pharmacy. She doesn't need a health portal to connect them. She has proof of every access her agent made on her behalf."

generate "pp-aria" "Sarah delegates: quote, why is my prescription notification late? End quote. The delegation credential arrives — signed by Sarah's key, scoped to medical queries only, ten-minute expiry. Aria's operating authority is specific, bounded, cryptographically enforced.

First query: One Medical SoMa's clinic system. Aria presents the delegation chain. The clinic verifies: Aria's key traces to Sarah's patient key. Scope covers medical record queries. The clinic returns appointment data under its own policy — it decides what to share, not the platform, not Aria. The clinic signs an access receipt.

Second query: MediMart Pharmacy. Different organization, different genesis key, different policy engine. But the same trust primitives. The pharmacy verifies Aria's delegation, checks scope, and returns prescription status. Pharmacy signs its own access receipt. Two receipts from two strangers, both chaining back to Sarah's original intent.

Synthesis: the appointment was rescheduled, which pushed the notification window past the pharmacy's fill date. The prescription has been ready for two days. Aria generates a synthesis receipt linking all four entries: intent, clinic, pharmacy, answer. Sarah can audit every cross-organizational access. No shared infrastructure needed. Just cryptographic math and portable trust."

generate "pp-ray" "Pickup at One Medical SoMa — medical center runs. Ray's done these before. The passenger, Sarah, gets in with her phone out, talking to her AI about prescriptions. Normal enough.

What's not normal is the credential exchange. Before the ride starts, Ray presents his driver chain — same as always. But Sarah's chain links to something deeper: a medical query delegation. Ray's ride receipt chains into a provenance trail that spans a clinic and a pharmacy.

En route to MediMart. Ray drives, Sarah's AI works. The ride receipt is building alongside medical access receipts. Three different organizations, three different policies, one trust layer underneath.

Drop-off at the pharmacy. Ray's trust score ticks up. But he notices something in his receipt: his fare is one link in a chain that spans three organizations. His ride didn't just get someone from A to B. It connected two healthcare systems that have never talked to each other. The trust infrastructure made it all one verifiable chain."

generate "pp-dispatch" "A ride request originates from One Medical SoMa — Sarah needs to get to MediMart Pharmacy. Standard fare computation: eleven-twenty, estimated eight minutes. Dispatch matches Driver Ray, closest available.

But this ride illustrates why open infrastructure matters more than any single marketplace. On Uber or Lyft, a ride is just a ride. The platform takes you from point A to point B, collects its commission, and that's the end of the story. The ride data lives in the platform's silo, useful only to the platform.

In ZeroPoint, this ride chains into something larger. Sarah's AI agent, Aria, has been querying across organizational boundaries — a clinic and a pharmacy. Two independent access receipts already link back to Sarah's delegation credential. Dispatch routes the ride like any other. But underneath, the receipt chain connects three organizations that have never shared a database, never signed an integration contract, never even heard of each other.

When the ride completes, Dispatch holds its copy of the chain: delegation, clinic access, ride, pharmacy access, synthesis. Five different receipt types, three different organizations, one governance layer. This is what general-purpose trust infrastructure looks like — and it's what you can never build on top of a closed platform that only cares about rides. The trust layer doesn't belong to any one marketplace. It belongs to the participants."

echo ""
echo "Done. Generated 33 per-agent narration files in ${OUT_DIR}/"
echo "Voice: Amy (en_US-amy-medium) @ 1.35x"
echo "Noise: scale=${NOISE_SCALE} w=${NOISE_W}"
