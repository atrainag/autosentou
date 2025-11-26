"""
services/utils/interactive_confirmer.py
Interactive vulnerability validation using Playwright + Gemini
Adapted from web_analysis_alternative/Tools/confirmer.py
"""
import logging
import json
import re
from typing import Dict, Any, Optional, List
from datetime import datetime
from playwright.async_api import Page, TimeoutError as PlaywrightTimeout

from services.ai.ai_service import get_ai_service

logger = logging.getLogger(__name__)


class InteractiveConfirmer:
    """
    LLM-powered vulnerability validator with Playwright browser automation.

    Workflow:
    1. Create validation plan (what to look for)
    2. Capture initial page state
    3. Plan interactions (if needed)
    4. Execute interactions (click, fill, submit)
    5. Capture final state
    6. Analyze with Gemini: CONFIRMED vs FALSE_POSITIVE

    XSS Testing Workflow:
    1. Detect input fields on page
    2. AI generates context-aware XSS payloads (10 payloads)
    3. Test each payload with Playwright
    4. Learn from failures to bypass filters
    5. Confirm execution visually
    """

    def __init__(self, timeout: int = 10000):
        """
        Initialize Interactive Confirmer.

        Args:
            timeout: Playwright timeout in milliseconds (default: 10000)
        """
        self.timeout = timeout
        self.ai_service = get_ai_service()
        self.xss_learning_history = []  # Track what payloads worked/failed

        logger.info("InteractiveConfirmer initialized with Gemini AI + XSS testing")

    async def confirm_finding(
        self,
        page: Page,
        finding: Dict[str, Any],
        url: str
    ) -> Dict[str, Any]:
        """
        Validate a finding interactively.

        Args:
            page: Playwright page object (already navigated to URL)
            finding: Finding dict from web analysis
            url: URL being tested

        Returns:
            Validation result with status (CONFIRMED/FALSE_POSITIVE) and evidence
        """
        result = {
            'finding_id': finding.get('id'),
            'vuln_type': finding.get('vuln_type'),
            'url': url,
            'status': 'PENDING',
            'evidence': {},
            'trace': []
        }

        try:
            result['trace'].append(f"[{self._timestamp()}] Starting interactive validation for {finding.get('vuln_type')}")
            result['trace'].append(f"[{self._timestamp()}] Target: {url}")

            # Step 1: Create validation plan
            validation_plan = await self._create_validation_plan(page, finding, url)
            result['validation_plan'] = validation_plan
            result['trace'].append(f"[{self._timestamp()}] Validation strategy: {validation_plan.get('validation_strategy')}")

            # Step 2: Capture initial state
            initial_state = await self._capture_page_state(page)
            result['initial_state'] = initial_state
            result['trace'].append(f"[{self._timestamp()}] Captured initial state")

            # Step 3: Plan interactions
            interaction_plan = await self._plan_interaction(page, finding, initial_state, validation_plan)
            result['interaction_plan'] = interaction_plan

            # Step 4: Execute interactions (if needed)
            if interaction_plan.get('requires_interaction', False):
                result['trace'].append(f"[{self._timestamp()}] Executing {len(interaction_plan.get('actions', []))} interactions")
                network_data = await self._execute_interactions(page, interaction_plan, result)
                result['network_capture'] = network_data
                await page.wait_for_timeout(1500)
            else:
                result['trace'].append(f"[{self._timestamp()}] No interaction required")

            # Step 5: Capture final state
            final_state = await self._capture_page_state(page)
            result['final_state'] = final_state
            result['trace'].append(f"[{self._timestamp()}] Captured final state")

            # Step 6: Analyze with Gemini
            result['trace'].append(f"[{self._timestamp()}] Analyzing with Gemini AI")
            analysis = await self._analyze_with_gemini(finding, validation_plan, initial_state, final_state, interaction_plan, result)

            result['status'] = analysis.get('status', 'AMBIGUOUS')
            result['reasoning'] = analysis.get('reasoning', '')
            result['evidence'] = analysis.get('evidence', {})

            result['trace'].append(f"[{self._timestamp()}] Validation complete: {result['status']}")

            logger.info(f"✓ Confirmed finding: {finding.get('vuln_type')} → {result['status']}")

        except Exception as e:
            logger.error(f"Interactive confirmation failed: {e}")
            result['status'] = 'ERROR'
            result['error'] = str(e)
            result['trace'].append(f"[{self._timestamp()}] ERROR: {str(e)}")

        return result

    def _timestamp(self) -> str:
        """Get current timestamp for trace."""
        return datetime.now().strftime("%H:%M:%S")

    async def _create_validation_plan(
        self,
        page: Page,
        finding: Dict[str, Any],
        url: str
    ) -> Dict[str, Any]:
        """
        Create validation plan using Gemini.
        Determines what to look for and how to validate.
        """
        page_title = await page.title()
        visible_text = await page.inner_text('body')
        visible_text_preview = visible_text[:1000]

        prompt = f"""You are a Verification Engine for vulnerability scanning.
Create a validation plan to confirm this vulnerability.

**VULNERABILITY:**
Type: {finding.get('vuln_type', 'Unknown')}
Vector: {finding.get('vector', 'Unknown')}
Target URL: {url}
Evidence: {finding.get('evidence', {}).get('raw_snippet', 'N/A')[:200]}

**CURRENT PAGE:**
Title: {page_title}
Visible Text (first 1000 chars):
{visible_text_preview}

**OUTPUT (JSON ONLY):**
{{
  "validation_strategy": "direct_observation" | "interaction_required" | "cannot_validate",
  "what_to_look_for": ["Exact strings or patterns to find"],
  "expected_proof": "What confirms this vulnerability",
  "interaction_needed": {{
    "required": true/false,
    "reason": "Why interaction is needed"
  }}
}}
"""

        try:
            response = self.ai_service.generate(prompt)
            plan = self._parse_json_response(response)

            if not plan:
                # Fallback plan
                return self._get_fallback_plan(finding)

            return plan

        except Exception as e:
            logger.error(f"Failed to create validation plan: {e}")
            return self._get_fallback_plan(finding)

    async def _capture_page_state(self, page: Page) -> Dict[str, Any]:
        """Capture current page state."""
        state = {
            'title': '',
            'visible_text': '',
            'interactive_elements': []
        }

        try:
            state['title'] = await page.title()
            state['visible_text'] = (await page.inner_text('body'))[:5000]

            # Find forms
            forms = await page.locator('form').all()
            for form in forms[:5]:
                try:
                    inputs = await form.locator('input, textarea, select').all()
                    fields = []
                    for inp in inputs[:20]:
                        try:
                            field_info = {
                                'name': await inp.get_attribute('name') or '',
                                'id': await inp.get_attribute('id') or '',
                                'type': await inp.get_attribute('type') or 'text',
                                'placeholder': await inp.get_attribute('placeholder') or ''
                            }
                            if field_info['name'] or field_info['id']:
                                fields.append(field_info)
                        except:
                            pass

                    if fields:
                        state['interactive_elements'].append({
                            'type': 'form',
                            'action': await form.get_attribute('action') or '',
                            'fields': fields
                        })
                except:
                    pass

        except Exception as e:
            logger.error(f"Error capturing state: {e}")

        return state

    async def _plan_interaction(
        self,
        page: Page,
        finding: Dict[str, Any],
        initial_state: Dict[str, Any],
        validation_plan: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Determine if interaction is needed using Gemini.
        NOTE: Form submission is SKIPPED per your requirement.
        """
        interactive_elements = initial_state.get('interactive_elements', [])
        visible_text = initial_state.get('visible_text', '')[:1000]

        prompt = f"""You are a Browser Controller determining if UI interaction is needed.

**VULNERABILITY:**
Type: {finding.get('vuln_type')}
Vector: {finding.get('vector')}
Expected Proof: {validation_plan.get('expected_proof', 'N/A')}

**PAGE STATE:**
Title: {initial_state.get('title')}
Visible Text: {visible_text}
Forms Found: {len([e for e in interactive_elements if e['type'] == 'form'])}

**IMPORTANT: FORM SUBMISSION IS DISABLED**
You can only click buttons/links. Do NOT plan form filling or submission.

**OUTPUT (JSON ONLY):**
{{
  "requires_interaction": true/false,
  "reasoning": "Why interaction is/isn't needed",
  "actions": [
    {{
      "type": "click" | "wait",
      "target_description": "What this accomplishes",
      "selector_hint": "Exact visible text to click"
    }}
  ]
}}

If content is already visible, set requires_interaction to false.
"""

        try:
            response = self.ai_service.generate(prompt)
            plan = self._parse_json_response(response)

            if not plan:
                return {'requires_interaction': False, 'actions': []}

            return plan

        except Exception as e:
            logger.error(f"Interaction planning failed: {e}")
            return {'requires_interaction': False, 'actions': []}

    async def _execute_interactions(
        self,
        page: Page,
        interaction_plan: Dict[str, Any],
        result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute planned interactions (clicks only, no form submission).
        """
        actions = interaction_plan.get('actions', [])[:3]  # Max 3 actions
        network_requests = []

        # Network capture
        def capture_request(request):
            if request.method in ['POST', 'GET']:
                network_requests.append({
                    'method': request.method,
                    'url': request.url,
                    'headers': dict(request.headers)
                })

        page.on('request', capture_request)

        for action in actions:
            action_type = action.get('type', 'click')
            selector_hint = action.get('selector_hint', '')

            result['trace'].append(f"[{self._timestamp()}] Executing: {action_type} on '{selector_hint}'")

            try:
                if action_type == 'click':
                    # Try multiple selectors
                    clicked = False

                    # Try button with text
                    try:
                        await page.click(f"button:has-text('{selector_hint}')", timeout=3000)
                        result['trace'].append(f"[{self._timestamp()}] ✓ Clicked button")
                        clicked = True
                    except:
                        pass

                    if not clicked:
                        # Try any element with text
                        try:
                            await page.click(f"text='{selector_hint}'", timeout=3000)
                            result['trace'].append(f"[{self._timestamp()}] ✓ Clicked element")
                            clicked = True
                        except:
                            pass

                    if not clicked:
                        result['trace'].append(f"[{self._timestamp()}] ✗ Could not click: {selector_hint}")

                elif action_type == 'wait':
                    await page.wait_for_timeout(2000)
                    result['trace'].append(f"[{self._timestamp()}] ✓ Waited 2 seconds")

            except Exception as e:
                result['trace'].append(f"[{self._timestamp()}] ✗ Interaction failed: {e}")

        page.remove_listener('request', capture_request)

        return {
            'network_requests': network_requests,
            'total_requests': len(network_requests)
        }

    async def _analyze_with_gemini(
        self,
        finding: Dict[str, Any],
        validation_plan: Dict[str, Any],
        initial_state: Dict[str, Any],
        final_state: Dict[str, Any],
        interaction_plan: Dict[str, Any],
        result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Analyze interactive session with Gemini to determine if finding is confirmed.
        """
        interaction_performed = interaction_plan.get('requires_interaction', False)

        if interaction_performed:
            state_section = f"""
**INITIAL STATE (Before Interaction):**
{initial_state.get('visible_text', '')[:1500]}

**FINAL STATE (After Interaction):**
{final_state.get('visible_text', '')[:1500]}
"""
        else:
            state_section = f"""
**PAGE STATE:**
{final_state.get('visible_text', '')[:3000]}
"""

        prompt = f"""You are a Forensic Validator determining if a vulnerability is REAL or FALSE_POSITIVE.

**VULNERABILITY CLAIM:**
Type: {finding.get('vuln_type')}
Vector: {finding.get('vector')}
Expected Proof: {validation_plan.get('expected_proof', 'N/A')}

**OBSERVATIONS:**
Page Title: {final_state.get('title')}
{state_section}

**VALIDATION RULES:**
1. Status 404/500 without specific evidence → FALSE_POSITIVE
2. Keyword only in error message (e.g., "cgi.exe not found") → FALSE_POSITIVE
3. Content mismatch (expecting binary, got HTML) → FALSE_POSITIVE
4. Generic headers without version (e.g., "Server: Apache") → FALSE_POSITIVE

**OUTPUT (JSON ONLY):**
{{
  "status": "CONFIRMED" | "FALSE_POSITIVE" | "AMBIGUOUS",
  "reasoning": "One sentence explanation",
  "evidence": {{
    "found_snippet": "Exact quote from page",
    "why_it_matches": "Explanation"
  }}
}}
"""

        try:
            response = self.ai_service.generate(prompt)
            analysis = self._parse_json_response(response)

            if not analysis:
                return {
                    'status': 'AMBIGUOUS',
                    'reasoning': 'Failed to parse Gemini response',
                    'evidence': {}
                }

            return analysis

        except Exception as e:
            logger.error(f"Gemini analysis failed: {e}")
            return {
                'status': 'ERROR',
                'reasoning': f'Analysis error: {str(e)}',
                'evidence': {}
            }

    async def test_xss_on_page(
        self,
        page: Page,
        url: str
    ) -> Dict[str, Any]:
        """
        Test page for XSS vulnerabilities with AI-generated context-aware payloads.

        Args:
            page: Playwright page object
            url: URL being tested

        Returns:
            XSS test results with confirmed payloads
        """
        result = {
            'url': url,
            'input_fields_found': 0,
            'payloads_tested': 0,
            'xss_confirmed': False,
            'successful_payloads': [],
            'failed_payloads': [],
            'trace': []
        }

        try:
            result['trace'].append(f"[{self._timestamp()}] Starting XSS testing on {url}")

            # Step 1: Detect input fields
            input_fields = await self._detect_input_fields(page)
            result['input_fields_found'] = len(input_fields)

            if not input_fields:
                result['trace'].append(f"[{self._timestamp()}] No input fields found")
                return result

            result['trace'].append(f"[{self._timestamp()}] Found {len(input_fields)} input field(s)")

            # Test each input field
            for field_idx, field in enumerate(input_fields[:5], 1):  # Max 5 fields
                result['trace'].append(f"[{self._timestamp()}] Testing field {field_idx}/{min(len(input_fields), 5)}: {field.get('name', 'unnamed')}")

                # Step 2: AI generates context-aware payloads
                payloads = await self._generate_xss_payloads(field, page)
                result['trace'].append(f"[{self._timestamp()}] Generated {len(payloads)} payloads")

                # Step 3: Test each payload
                for payload_idx, payload in enumerate(payloads, 1):
                    result['payloads_tested'] += 1

                    result['trace'].append(f"[{self._timestamp()}] Testing payload {payload_idx}/{len(payloads)}: {payload[:50]}...")

                    # Test the payload
                    xss_detected = await self._test_xss_payload(page, field, payload)

                    if xss_detected:
                        result['xss_confirmed'] = True
                        result['successful_payloads'].append({
                            'field': field.get('name', 'unnamed'),
                            'payload': payload,
                            'field_context': field
                        })
                        result['trace'].append(f"[{self._timestamp()}] ✓ XSS CONFIRMED!")

                        # Add to learning history
                        self.xss_learning_history.append({
                            'payload': payload,
                            'success': True,
                            'field_type': field.get('type', 'text'),
                            'maxlength': field.get('maxlength')
                        })

                        # Don't test more payloads for this field if we found one that works
                        break
                    else:
                        result['failed_payloads'].append({
                            'field': field.get('name', 'unnamed'),
                            'payload': payload
                        })

                        # Add to learning history
                        self.xss_learning_history.append({
                            'payload': payload,
                            'success': False,
                            'field_type': field.get('type', 'text'),
                            'maxlength': field.get('maxlength')
                        })

                if result['xss_confirmed']:
                    # Don't test more fields if we already confirmed XSS
                    break

            result['trace'].append(f"[{self._timestamp()}] XSS testing complete: {'VULNERABLE' if result['xss_confirmed'] else 'SECURE'}")

        except Exception as e:
            logger.error(f"XSS testing failed: {e}")
            result['error'] = str(e)

        return result

    async def _detect_input_fields(self, page: Page) -> List[Dict[str, Any]]:
        """Detect input fields on the page."""
        fields = []

        try:
            # Find all input elements
            inputs = await page.locator('input, textarea').all()

            for inp in inputs[:10]:  # Max 10 fields
                try:
                    field_type = await inp.get_attribute('type') or 'text'
                    field_name = await inp.get_attribute('name') or await inp.get_attribute('id') or 'unnamed'
                    maxlength = await inp.get_attribute('maxlength')
                    placeholder = await inp.get_attribute('placeholder') or ''

                    # Skip password and hidden fields
                    if field_type in ['password', 'hidden', 'submit', 'button']:
                        continue

                    fields.append({
                        'selector': f'input[name="{field_name}"]' if field_name != 'unnamed' else 'input',
                        'name': field_name,
                        'type': field_type,
                        'maxlength': int(maxlength) if maxlength and maxlength.isdigit() else None,
                        'placeholder': placeholder
                    })
                except:
                    pass

        except Exception as e:
            logger.error(f"Error detecting input fields: {e}")

        return fields

    async def _generate_xss_payloads(
        self,
        field: Dict[str, Any],
        page: Page
    ) -> List[str]:
        """
        Generate context-aware XSS payloads using AI.

        Args:
            field: Field information
            page: Playwright page

        Returns:
            List of 10 XSS payloads
        """
        # Get page title for context
        page_title = await page.title()

        # Build learning context from history
        learning_context = ""
        if self.xss_learning_history:
            successful = [h for h in self.xss_learning_history if h['success']]
            failed = [h for h in self.xss_learning_history if not h['success']]

            if successful:
                learning_context += f"\n**Previously successful payloads:**\n"
                for s in successful[-3:]:  # Last 3 successes
                    learning_context += f"- {s['payload']} (field type: {s['field_type']})\n"

            if failed:
                learning_context += f"\n**Previously failed payloads (avoid similar):**\n"
                for f in failed[-5:]:  # Last 5 failures
                    learning_context += f"- {f['payload']} (likely filtered)\n"

        prompt = f"""You are an XSS Payload Generator for security testing.

**TARGET FIELD:**
Name: {field.get('name', 'unnamed')}
Type: {field.get('type', 'text')}
Maxlength: {field.get('maxlength', 'unlimited')}
Placeholder: {field.get('placeholder', 'N/A')}
Page Title: {page_title}

{learning_context}

**TASK:** Generate 10 context-aware XSS payloads optimized for this field.

**RULES:**
1. If maxlength is set, payloads MUST fit within that limit
2. Vary techniques: <script>, <img>, <svg>, event handlers, DOM-based
3. Include encoding bypass attempts if previous payloads failed
4. Learn from history: If "script" keyword failed, try alternatives
5. Prioritize short, effective payloads

**OUTPUT (JSON ONLY):**
{{
  "payloads": [
    "payload1",
    "payload2",
    ...
    "payload10"
  ],
  "reasoning": "Why these payloads were chosen for this field"
}}
"""

        try:
            response = self.ai_service.generate(prompt)
            result = self._parse_json_response(response)

            if result and 'payloads' in result:
                return result['payloads'][:10]  # Max 10
            else:
                # Fallback to basic payloads
                return self._get_fallback_xss_payloads(field)

        except Exception as e:
            logger.error(f"AI payload generation failed: {e}")
            return self._get_fallback_xss_payloads(field)

    def _get_fallback_xss_payloads(self, field: Dict[str, Any]) -> List[str]:
        """Fallback XSS payloads if AI fails."""
        maxlength = field.get('maxlength')

        payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><script>alert(1)</script>',
            '<svg onload=alert(1)>',
            'javascript:alert(1)',
            '<iframe src=javascript:alert(1)>',
            '<body onload=alert(1)>',
            '<img src=x onerror=alert(1)/>',
            '\'><script>alert(1)</script>',
            '<svg/onload=alert(1)>'
        ]

        # Filter by maxlength if set
        if maxlength:
            payloads = [p for p in payloads if len(p) <= maxlength]

        return payloads[:10]

    async def _test_xss_payload(
        self,
        page: Page,
        field: Dict[str, Any],
        payload: str
    ) -> bool:
        """
        Test XSS payload by injecting it and checking for execution.

        Args:
            page: Playwright page
            field: Field information
            payload: XSS payload to test

        Returns:
            True if XSS confirmed, False otherwise
        """
        try:
            # Set up alert detection
            alert_fired = False

            def handle_dialog(dialog):
                nonlocal alert_fired
                alert_fired = True
                dialog.dismiss()

            page.on('dialog', handle_dialog)

            # Fill the field with payload
            selector = field.get('selector', 'input')
            await page.fill(selector, payload)

            # Trigger by pressing Enter or clicking submit
            await page.press(selector, 'Enter')

            # Wait a bit for alert
            await page.wait_for_timeout(1000)

            # Remove handler
            page.remove_listener('dialog', handle_dialog)

            return alert_fired

        except Exception as e:
            logger.debug(f"Error testing XSS payload: {e}")
            return False

    def _parse_json_response(self, response: str) -> Optional[Dict[str, Any]]:
        """Parse JSON from Gemini response."""
        try:
            # Remove markdown code blocks
            response_text = response.strip()
            if '```json' in response_text:
                response_text = response_text.split('```json')[1].split('```')[0]
            elif '```' in response_text:
                response_text = response_text.split('```')[1].split('```')[0]

            # Try JSON parse
            return json.loads(response_text.strip())

        except json.JSONDecodeError:
            # Try regex extraction
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group(0))
                except:
                    pass

            logger.error(f"Failed to parse JSON from Gemini response")
            return None

    def _get_fallback_plan(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback validation plan based on vulnerability type."""
        vuln_type = finding.get('vuln_type', '').lower()

        if 'information disclosure' in vuln_type or 'status' in vuln_type:
            return {
                'validation_strategy': 'direct_observation',
                'what_to_look_for': ['version', 'server', 'metrics', 'internal'],
                'expected_proof': 'Sensitive information visible on page',
                'interaction_needed': {'required': False}
            }
        elif 'api' in vuln_type or 'swagger' in vuln_type:
            return {
                'validation_strategy': 'direct_observation',
                'what_to_look_for': ['api', 'endpoint', 'swagger', 'openapi'],
                'expected_proof': 'API documentation exposed',
                'interaction_needed': {'required': False}
            }
        else:
            return {
                'validation_strategy': 'direct_observation',
                'what_to_look_for': [],
                'expected_proof': 'Vulnerability indicators present',
                'interaction_needed': {'required': False}
            }
