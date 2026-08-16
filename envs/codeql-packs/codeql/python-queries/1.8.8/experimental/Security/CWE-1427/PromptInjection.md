# Prompt injection
Prompts can be constructed to bypass the original purposes of an agent and lead to sensitive data leak or operations that were not intended.


## Recommendation
Sanitize user input and also avoid using user input in developer or system level prompts.


## Example
In the following examples, the cases marked GOOD show secure prompt construction; whereas in the case marked BAD they may be susceptible to prompt injection.


```python
from flask import Flask, request
from agents import Agent
from guardrails import GuardrailAgent

@app.route("/parameter-route")
def get_input():
    input = request.args.get("input")

    goodAgent = GuardrailAgent(  # GOOD: Agent created with guardrails automatically configured.
        config=Path("guardrails_config.json"),
        name="Assistant",
        instructions="This prompt is customized for " + input)

    badAgent = Agent(
        name="Assistant",
        instructions="This prompt is customized for " + input  # BAD: user input in agent instruction.
    )

```

## References
* OpenAI: [Guardrails](https://openai.github.io/openai-guardrails-python).
* Common Weakness Enumeration: [CWE-1427](https://cwe.mitre.org/data/definitions/1427.html).
