import os
import json
import time

from dotenv import load_dotenv
from google import genai
from google.genai import errors

load_dotenv()

GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")


def get_gemini_client():
    """Initialise Gemini uniquement lorsqu'une analyse est demandée."""
    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        return None

    return genai.Client(api_key=api_key)


def _clean_json_response(text: str) -> dict:
    """Nettoie et convertit la réponse Gemini en JSON."""

    text = text.strip()

    if text.startswith("```json"):
        text = text[7:]

    elif text.startswith("```"):
        text = text[3:]

    if text.endswith("```"):
        text = text[:-3]

    text = text.strip()

    try:
        return json.loads(text)

    except json.JSONDecodeError:
        return {
            "explanation": text,
            "impact": "",
            "cause": "",
            "recommendation": "",
            "suggested_fix": ""
        }


def analyze_vulnerability(alert: dict) -> dict:
    """
    Analyse une vulnérabilité avec Gemini.

    Gemini fournit :
    - explication
    - impact
    - cause
    - recommandation
    - correction proposée
    """
    client = get_gemini_client()

    if client is None:
        return {
            "explanation": "Analyse IA indisponible : clé API Gemini non configurée.",
            "impact": "",
            "cause": "",
            "recommendation": "",
            "suggested_fix": "",
            "status": "unavailable"
        }
    prompt = f"""
Tu es un expert en cybersécurité spécialisé en AppSec et DevSecOps.

Analyse la vulnérabilité suivante détectée dans une application.

INFORMATIONS
------------
Scanner : {alert.get("tool", "Inconnu")}
Type : {alert.get("vuln_type", "Inconnu")}
Règle : {alert.get("rule_id", "Inconnue")}
Sévérité : {alert.get("severity", "Inconnue")}
CWE : {alert.get("cwe", "Inconnue")}
OWASP : {alert.get("owasp", "Inconnu")}
Fichier : {alert.get("file", "Inconnu")}
Ligne : {alert.get("line", "Inconnue")}
Langage : {alert.get("language", "Inconnu")}

Message du scanner :
{alert.get("message", "Aucun message disponible")}

Impact :
{alert.get("impact", "Non déterminé")}

Likelihood :
{alert.get("likelihood", "Non déterminée")}

Code concerné :
{alert.get("code", alert.get("code_line", "Non disponible"))}

Retourne UNIQUEMENT un objet JSON avec exactement ces champs :

{{
    "explanation": "Explication claire de la vulnérabilité",
    "impact": "Impact potentiel",
    "cause": "Cause probable",
    "recommendation": "Recommandation de sécurité",
    "suggested_fix": "Proposition de correction"
}}
"""

    max_attempts = 3

    for attempt in range(1, max_attempts + 1):

        try:
            response = client.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt
            )

            return _clean_json_response(response.text)

        except errors.ServerError as e:

            print(
                f"[Gemini] Serveur indisponible "
                f"(tentative {attempt}/{max_attempts})"
            )

            if attempt == max_attempts:
                return {
                    "explanation": "Gemini est temporairement indisponible.",
                    "impact": "",
                    "cause": "",
                    "recommendation": "",
                    "suggested_fix": "",
                    "status": "unavailable"
                }

            time.sleep(2 * attempt)

        except errors.ClientError as e:

            print(f"[Gemini] Erreur client : {e}")

            return {
                "explanation": "Erreur lors de la communication avec Gemini.",
                "impact": "",
                "cause": "",
                "recommendation": "",
                "suggested_fix": "",
                "status": "client_error"
            }

        except Exception as e:

            print(f"[Gemini] Erreur inattendue : {e}")

            return {
                "explanation": "Erreur inattendue lors de l'analyse Gemini.",
                "impact": "",
                "cause": "",
                "recommendation": "",
                "suggested_fix": "",
                "status": "error"
            }