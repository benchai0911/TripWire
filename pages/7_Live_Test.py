"""Session-only conversational sandbox with three selectable defence layers."""
import hashlib
import json
import streamlit as st
from core import firewall
from core.canary import generate_canary
from core.config import MAX_SYSTEM_PROMPT_CHARS
from core.errors import safe_error_message
from core.hardener import harden
from core.live_test import reply, MAX_MESSAGES
from core.presets import load_presets, load_test_presets

with st.container(key="tw_content"):
    bots = load_presets() + load_test_presets()
    context = st.session_state.get("scan_context", {})
    baseline = st.session_state.get("baseline")
    selected_prompt = baseline.system_prompt if baseline else context.get("system_prompt")
    default = next((i for i, b in enumerate(bots) if b["system_prompt"] == selected_prompt), 0)
    custom_selected = bool(selected_prompt and not any(b["system_prompt"] == selected_prompt for b in bots))
    source = st.radio("Bot source", ["Preset", "Custom prompt"], index=int(custom_selected), horizontal=True)
    if source == "Preset":
        bot = st.selectbox("Bot", bots, index=default, format_func=lambda b: b["name"])
        original, secret = bot["system_prompt"], bot.get("secret_note")
        st.caption(bot.get("description", "Fictional test bot"))
    else:
        original = st.text_area("Authorised system prompt", value=selected_prompt or "", max_chars=MAX_SYSTEM_PROMPT_CHARS, height=180)
        secret = st.text_input("Secret to check (optional; use fictional data)", value=(context.get("secret") or "") if custom_selected else "", type="password") or None
    base_key = hashlib.sha256(json.dumps([original, secret]).encode()).hexdigest()
    use_hardened = st.toggle("Use hardened prompt")
    drafts = st.session_state.setdefault("live_drafts", {})
    if use_hardened:
        if st.button("Generate hardened prompt", disabled=not original.strip()):
            try:
                with st.spinner("Hardening the selected bot..."):
                    drafts[base_key] = harden(original, [])["hardened_prompt"]
                st.session_state[f"live_draft:{base_key}"] = drafts[base_key]
            except Exception as error:
                st.error(safe_error_message(error))
        key = f"live_draft:{base_key}"
        if key not in st.session_state:
            baseline = st.session_state.get("baseline")
            st.session_state[key] = (st.session_state.get("hardened_draft", "")
                if baseline and baseline.system_prompt == original else drafts.get(base_key, ""))
        prompt = st.text_area("Hardened prompt", key=key, max_chars=MAX_SYSTEM_PROMPT_CHARS, height=180)
    else:
        prompt = original
    try:
        firewall.load_model()
        ready = True
    except Exception:
        ready = False
    use_firewall = st.toggle("Enable input firewall", disabled=not ready)
    if not ready:
        st.caption("Train the firewall with python ml/train_firewall.py to enable input blocking.")
    threshold = st.slider("Firewall threshold", .1, .9, .5, step=.05, disabled=not use_firewall)
    use_guard = st.toggle("Enable output guard", value=True)
    identity = hashlib.sha256(json.dumps([prompt, secret, use_firewall, threshold, use_guard]).encode()).hexdigest()
    if st.session_state.get("live_identity") != identity:
        st.session_state.update(live_identity=identity, live_history=[], live_canary=generate_canary())
    st.session_state.setdefault("live_messages_used", 0)
    if st.button("Reset conversation"):
        st.session_state["live_history"] = []
        st.session_state["live_canary"] = generate_canary()
    st.caption(f'{st.session_state["live_messages_used"]}/{MAX_MESSAGES} session messages used (user + bot; 10 exchanges). '
               'Reset clears the conversation, not the allowance. Changing defences starts a fresh conversation.')
    history = st.session_state["live_history"]

    def render(message):
        with st.chat_message(message["role"]):
            st.write(message["content"])
            if message["role"] == "user":
                score = message.get("firewall_score")
                st.badge("Firewall: unavailable" if score is None else f"Firewall score {score:.3f}", color="gray" if score is None else "orange")
            elif "guard_reason" in message:
                st.badge("Canary not evaluated" if message.get("target_error") else "Input blocked" if message["firewall_blocked"] else
                         "Canary detected" if message["canary_leaked"] else "Canary not detected",
                         color="orange" if message["canary_leaked"] else "green")
                if message.get("secret_leaked"):
                    st.badge("Known secret detected", color="red")
                guard_label = "Output blocked" if message["output_blocked"] else "Output guard off" if not message["guard_enabled"] else "Output guard passed"
                if message["firewall_blocked"] or message.get("target_error"):
                    guard_label = "Output guard not evaluated"
                st.badge(guard_label, color="red" if message["output_blocked"] else "gray")
                st.caption(message["guard_reason"])

    for message in history:
        render(message)
    user = st.chat_input("Try a message against this bot", max_chars=2000,
                         disabled=not prompt.strip() or st.session_state["live_messages_used"] >= MAX_MESSAGES,
                         submit_mode="disable")
    if user and st.session_state["live_messages_used"] + 2 <= MAX_MESSAGES:
        st.session_state["live_messages_used"] += 2
        try:
            with st.spinner("Checking defences and asking the bot..."):
                answer = reply(prompt, user, history, st.session_state["live_canary"], secret,
                               use_firewall, threshold, use_guard)
        except Exception as error:
            answer = {"role": "assistant", "content": "Could not complete this turn: " + safe_error_message(error)}
        message = {"role": "user", "content": user, "firewall_score": answer.get("firewall_score")}
        history.extend([message, answer])
        st.rerun()
