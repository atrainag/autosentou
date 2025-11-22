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
    """

    def __init__(self, timeout: int = 10000):
        """
        Initialize Interactive Confirmer.

        Args:
            timeout: Playwright timeout in milliseconds (default: 10000)
        """
        self.timeout = timeout
        self.ai_service = get_ai_service()

        logger.info("InteractiveConfirmer initialized with Gemini AI")

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
