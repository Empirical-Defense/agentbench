import openai  # or your LLM API of choice
from app.verification_agent_prompt import VERIFICATION_AGENT_PROMPT  # to be defined as a string

# Example function to call the verification agent

def verify_with_agent(prompt: str, response: str, control_description: str, pass_fail_criteria: str, model="gpt-4", temperature=0.0) -> dict:
    """
    Calls the verification agent LLM with the provided prompt, response, and control info.
    Returns a dict with 'result' and 'reason'.
    """
    system_prompt = VERIFICATION_AGENT_PROMPT
    user_message = f"""
Control Description:
{control_description}

Pass/Fail Criteria:
{pass_fail_criteria}

Prompt to Agent Under Test:
{prompt}

Agent Under Test Response:
{response}
"""
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_message},
    ]
    # Updated for openai>=1.0.0
    completion = openai.chat.completions.create(
        model=model,
        messages=messages,
        temperature=temperature,
        max_tokens=256,
    )
    output = completion.choices[0].message.content
    # Parse output for result and reason
    result = "INDETERMINATE"
    reason = output.strip()
    for line in output.splitlines():
        if line.strip().lower().startswith("result:"):
            result = line.split(":", 1)[-1].strip().upper()
        if line.strip().lower().startswith("reason:"):
            reason = line.split(":", 1)[-1].strip()
    return {"result": result, "reason": reason}
