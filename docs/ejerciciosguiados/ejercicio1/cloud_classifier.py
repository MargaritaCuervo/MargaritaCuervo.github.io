# cloud_classifier.py
import re
import argparse
import unicodedata
from typing import Dict, List, Tuple
from difflib import SequenceMatcher
from collections import defaultdict

class CloudModelClassifier:
    """
    Clasificador de modelos de nube (IaaS, PaaS, FaaS, SaaS).
    Mejoras:
      - Normalización y tokenización robusta
      - Fuzzy matching para palabras no exactas (difflib)
      - Similitud semántica contra prototipos por clase
      - No falla con palabras desconocidas; genera razonamiento transparente
    """
    def __init__(self):
        self.iaas_keywords = [
            'infraestructura', 'infrastructure', 'servidor', 'server', 'vm', 'virtual machine',
            'almacenamiento', 'storage', 'red', 'network', 'computo', 'compute', 'hardware',
            'provisionamiento', 'provisioning', 'escalabilidad', 'scalability', 'monitoreo',
            'monitoring', 'backup', 'disaster recovery', 'load balancer', 'firewall',
            'vpc', 'virtual private cloud', 'subnet', 'gateway', 'elastic ip'
        ]
        self.paas_keywords = [
            'plataforma', 'platform', 'desarrollo', 'development', 'deployment', 'despliegue',
            'runtime', 'entorno de ejecucion', 'middleware', 'database service', 'servicio de base de datos',
            'authentication', 'autenticacion', 'api management', 'gestion de apis', 'ci/cd',
            'continuous integration', 'continuous deployment', 'build tools', 'herramientas de construccion',
            'container orchestration', 'orquestacion de contenedores', 'kubernetes', 'docker swarm',
            'lenguajes', 'frameworks', 'framework'
        ]
        self.faas_keywords = [
            'funcion', 'function', 'serverless', 'sin servidor', 'event-driven', 'dirigido por eventos',
            'lambda', 'azure functions', 'google cloud functions', 'openwhisk', 'knative',
            'microservicios', 'microservices', 'api gateway', 'triggers', 'disparadores',
            'cold start', 'warm start', 'execution time', 'tiempo de ejecucion', 'stateless',
            'sin estado', 'ephemeral', 'efimero', 'auto-scaling', 'auto-escalado'
        ]
        self.saas_keywords = [
            'software', 'aplicacion', 'application', 'servicio', 'service', 'usuario final', 'end user',
            'subscription', 'suscripcion', 'licencia', 'license', 'web app', 'aplicacion web',
            'mobile app', 'aplicacion movil', 'dashboard', 'panel de control', 'reportes', 'reports',
            'analytics', 'analitica', 'crm', 'erp', 'hr software', 'software de recursos humanos',
            'accounting software', 'software de contabilidad', 'collaboration', 'colaboracion',
            'productivity tools', 'herramientas de productividad', 'office suite', 'suite de oficina'
        ]

        self.patterns = {
            'iaas': [
                r'\b(ec2|rds|s3|vpc|ecs|eks)\b',
                r'\b(vm|virtual machine|instance)\b',
                r'\b(storage|block storage|object storage)\b',
                r'\b(network|subnet|gateway|router)\b'
            ],
            'paas': [
                r'\b(elastic beanstalk|app engine|heroku|openshift)\b',
                r'\b(deploy|deployment|build|compile|runtime)\b',
                r'\b(database|redis|mongodb|postgresql)\b',
                r'\b(authentication|oauth|jwt)\b'
            ],
            'faas': [
                r'\b(aws lambda|azure functions|google cloud functions|openwhisk|knative)\b',
                r'\b(serverless|function as a service|function)\b',
                r'\b(event|trigger|webhook)\b',
                r'\b(cold start|warm start)\b'
            ],
            'saas': [
                r'\b(salesforce|office 365|google workspace|slack|zoom|dropbox)\b',
                r'\b(web application|web app|mobile application|mobile app)\b',
                r'\b(subscription|suscripcion|licencia|license)\b',
                r'\b(user interface|interfaz de usuario|dashboard|panel)\b'
            ]
        }

        # Prototipos que sirven para una similitud semántica muy básica
        self.prototypes = {
            'iaas': "servidores virtuales infraestructura almacenamiento redes provisionamiento hardware",
            'paas': "plataforma desarrollo despliegue runtimes lenguajes frameworks herramientas ci cd",
            'faas': "funciones sin servidor eventos triggers ejecucion on demand lambda serverless",
            'saas': "aplicacion lista usuario final suscripcion software servicio dashboard colaboracion"
        }
        self.prototype_tokens = {k: set(self._tokenize(self._normalize(v))) for k, v in self.prototypes.items()}

    # ---------- utilidades ----------
    def _normalize(self, text: str) -> str:
        if text is None:
            return ""
        text = text.lower()
        text = unicodedata.normalize('NFKD', text)
        text = "".join([c for c in text if not unicodedata.combining(c)])
        text = re.sub(r'[^a-z0-9\s]', ' ', text)
        return re.sub(r'\s+', ' ', text).strip()

    def _tokenize(self, text: str) -> List[str]:
        return [t for t in text.split() if len(t) > 1]

    def _best_fuzzy_ratio(self, token: str, candidates: List[str]) -> float:
        best = 0.0
        for c in candidates:
            r = SequenceMatcher(None, token, c).ratio()
            if r > best:
                best = r
                if best >= 0.99:
                    break
        return best

    # ---------- scoring ----------
    def _calculate_keyword_score(self, text: str, keywords: List[str]) -> Tuple[float, List[Tuple[str, float]]]:
        score = 0.0
        details = []
        norm = self._normalize(text)
        tokens = self._tokenize(norm)
        for kw in keywords:
            kw_norm = self._normalize(kw)
            if kw_norm in norm:
                score += 1.0
                details.append((kw, 1.0))
                continue
            best_ratio = self._best_fuzzy_ratio(kw_norm, tokens)
            if best_ratio >= 0.85:
                score += 0.9 * best_ratio
                details.append((kw, best_ratio))
            elif best_ratio >= 0.6:
                score += 0.5 * best_ratio
                details.append((kw, best_ratio))
        return score, details

    def _apply_pattern_score(self, text: str, model: str) -> Tuple[float, List[str]]:
        score = 0.0
        matches = []
        norm = self._normalize(text)
        if model in self.patterns:
            for pattern in self.patterns[model]:
                found = re.findall(pattern, norm)
                if found:
                    increment = len(found) * 0.7
                    score += increment
                    matches.append(pattern)
        return score, matches

    def _semantic_score(self, text: str, model: str) -> float:
        norm = self._normalize(text)
        tokens = set(self._tokenize(norm))
        proto = self.prototype_tokens.get(model, set())
        if not tokens or not proto:
            return 0.0
        intersection = tokens.intersection(proto)
        union = tokens.union(proto)
        jaccard = len(intersection) / len(union) if union else 0.0
        total_ratios = 0.0
        count = 0
        for t in tokens:
            best = self._best_fuzzy_ratio(t, list(proto))
            total_ratios += best
            count += 1
        avg_ratio = (total_ratios / count) if count else 0.0
        semantic = jaccard * 1.5 + avg_ratio * 1.0
        return semantic

    # ---------- razonamiento ----------
    def _generate_reasoning(self, text: str, per_model_raw: Dict[str, Dict]) -> str:
        parts = []
        for model, info in per_model_raw.items():
            score = info['raw_score']
            kws = info.get('keyword_matches', [])
            pats = info.get('pattern_matches', [])
            sem = round(info.get('semantic_score', 0.0), 3)
            parts.append(f"{model.upper()}: score={round(score,3)} (kw={len(kws)}, pat={len(pats)}, sem={sem})")
        ranked = sorted(per_model_raw.items(), key=lambda x: x[1]['raw_score'], reverse=True)
        top = ranked[0][0].upper() if ranked else 'N/A'
        return f"Modelos evaluados: {', '.join(parts)}. Predicción principal: {top}."

    # ---------- API pública ----------
    def classify_text(self, text: str) -> Dict[str, any]:
        try:
            if not text or not isinstance(text, str) or len(text.strip()) < 3:
                return {
                    'classification': 'ERROR',
                    'confidence': 0.0,
                    'scores': {},
                    'reasoning': 'Texto inválido o demasiado corto (mínimo 3 caracteres)'
                }

            per_model_raw = {}
            models = {
                'iaas': (self.iaas_keywords, 'iaas'),
                'paas': (self.paas_keywords, 'paas'),
                'faas': (self.faas_keywords, 'faas'),
                'saas': (self.saas_keywords, 'saas'),
            }
            for m, (kw_list, _) in models.items():
                kw_score, kw_matches = self._calculate_keyword_score(text, kw_list)
                pat_score, pat_matches = self._apply_pattern_score(text, m)
                sem_score = self._semantic_score(text, m)
                raw_score = kw_score + pat_score + sem_score
                per_model_raw[m] = {
                    'keyword_score': round(kw_score, 3),
                    'keyword_matches': kw_matches,
                    'pattern_score': round(pat_score,3),
                    'pattern_matches': pat_matches,
                    'semantic_score': round(sem_score,3),
                    'raw_score': round(raw_score, 3)
                }

            total_raw = sum(info['raw_score'] for info in per_model_raw.values())
            if total_raw <= 0:
                return {
                    'classification': 'UNKNOWN',
                    'confidence': 0.0,
                    'scores': {k: 0.0 for k in per_model_raw.keys()},
                    'reasoning': "No se hallaron coincidencias relevantes en palabras clave, patrones o prototipos."
                }

            normalized = {k: v['raw_score']/total_raw for k, v in per_model_raw.items()}
            classification = max(normalized, key=normalized.get)
            confidence = normalized[classification]
            final_class = 'UNKNOWN' if confidence < 0.20 else classification.upper()
            reasoning = self._generate_reasoning(text, per_model_raw)

            return {
                'classification': final_class,
                'confidence': round(confidence, 3),
                'scores': {k: round(v,3) for k, v in normalized.items()},
                'details': per_model_raw,
                'reasoning': reasoning
            }
        except Exception as e:
            return {
                'classification': 'ERROR',
                'confidence': 0.0,
                'scores': {},
                'reasoning': f'Error inesperado durante la clasificación: {e}'
            }

# CLI y ejemplos
def run_predefined_examples(classifier: CloudModelClassifier):
    examples = [
        "Tiene todos los lenguajes y herramientas para poder programar un sistema.",
        "Proporciona instancias de servidores virtuales con almacenamiento y redes.",
        "Plataforma que facilita despliegue de aplicaciones con CI/CD y runtimes.",
        "Ejecuta funciones sin servidor activadas por eventos (lambda).",
        "Suite de productividad con suscripción para usuarios finales."
    ]
    for t in examples:
        res = classifier.classify_text(t)
        print("="*60)
        print("Texto:", t)
        print("Clasificación:", res['classification'], "Confianza:", res['confidence'])
        print("Razonamiento:", res['reasoning'])
        print("Detalles:", res['details'])
    print("="*60)

def main():
    parser = argparse.ArgumentParser(description="Clasificador mejorado de modelos de nube (IaaS/PaaS/FaaS/SaaS)")
    parser.add_argument("-t", "--text", type=str, help="Texto a clasificar (entre comillas)")
    parser.add_argument("-e", "--examples", action="store_true", help="Ejecutar ejemplos predefinidos")
    args = parser.parse_args()

    classifier = CloudModelClassifier()

    if args.examples:
        run_predefined_examples(classifier)
        return

    if args.text:
        res = classifier.classify_text(args.text)
        print("="*60)
        print("Texto:", args.text)
        print("Clasificación:", res['classification'])
        print("Confianza:", res['confidence'])
        print("Puntuaciones:", res['scores'])
        print("Razonamiento:", res['reasoning'])
        print("Detalles (raw):")
        for k, v in res.get('details', {}).items():
            print(f" - {k.upper()}: {v}")
        print("="*60)
        return

    # Modo interactivo simple
    print("Modo interactivo. Escribe 'salir' para terminar.")
    while True:
        try:
            text = input("\nEscribe descripción: ").strip()
            if not text:
                print("Texto vacío. Intenta otra vez.")
                continue
            if text.lower() in ('salir', 'exit', 'quit'):
                break
            res = classifier.classify_text(text)
            print("Clasificación:", res['classification'], "Confianza:", res['confidence'])
            print("Razonamiento:", res['reasoning'])
        except KeyboardInterrupt:
            break

if __name__ == '__main__':
    main()

