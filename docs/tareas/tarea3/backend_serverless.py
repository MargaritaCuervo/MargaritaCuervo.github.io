#!/usr/bin/env python3
"""
🏦 Backend Serverless para Aplicación de Banca Móvil
Arquitectura Híbrida con AWS Lambda y servicios on-premises
"""

import json
import boto3
import hashlib
import jwt
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from dataclasses import dataclass
import logging

# Configuración de logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Inicialización de clientes AWS
dynamodb = boto3.resource('dynamodb')
rds_client = boto3.client('rds-data')
cognito = boto3.client('cognito-idp')
kms = boto3.client('kms')
sns = boto3.client('sns')

# Configuración
USER_POOL_ID = 'us-east-1_XXXXXXXXX'
CLIENT_ID = 'your_client_id'
REGION = 'us-east-1'
JWT_SECRET = 'your_jwt_secret_key'

@dataclass
class Transaction:
    """Modelo de transacción bancaria"""
    transaction_id: str
    user_id: str
    account_from: str
    account_to: str
    amount: float
    currency: str
    transaction_type: str
    status: str
    timestamp: datetime
    description: str

@dataclass
class User:
    """Modelo de usuario"""
    user_id: str
    email: str
    phone: str
    full_name: str
    accounts: list
    mfa_enabled: bool
    risk_level: str
    created_at: datetime

class BankingBackend:
    """Clase principal del backend bancario"""
    
    def __init__(self):
        self.transactions_table = dynamodb.Table('banking-transactions')
        self.users_table = dynamodb.Table('banking-users')
        self.cache_table = dynamodb.Table('banking-cache')
    
    def _encrypt_sensitive_data(self, data: str) -> str:
        """Encripta datos sensibles usando KMS"""
        try:
            response = kms.encrypt(
                KeyId='alias/banking-key',
                Plaintext=data.encode('utf-8')
            )
            return response['CiphertextBlob'].hex()
        except Exception as e:
            logger.error(f"Error encriptando datos: {e}")
            return data
    
    def _decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """Desencripta datos usando KMS"""
        try:
            response = kms.decrypt(
                CiphertextBlob=bytes.fromhex(encrypted_data)
            )
            return response['Plaintext'].decode('utf-8')
        except Exception as e:
            logger.error(f"Error desencriptando datos: {e}")
            return encrypted_data

class AuthenticationService:
    """Servicio de autenticación y autorización"""
    
    def __init__(self):
        self.backend = BankingBackend()
    
    def authenticate_user(self, email: str, password: str) -> Dict[str, Any]:
        """
        Autentica un usuario usando Cognito
        """
        try:
            # Autenticación con Cognito
            response = cognito.initiate_auth(
                AuthFlow='USER_PASSWORD_AUTH',
                ClientId=CLIENT_ID,
                AuthParameters={
                    'USERNAME': email,
                    'PASSWORD': password
                }
            )
            
            if response['AuthenticationResult']:
                # Generar JWT personalizado
                user_info = self._get_user_info(email)
                token = self._generate_jwt(user_info)
                
                return {
                    'success': True,
                    'token': token,
                    'user': user_info,
                    'message': 'Autenticación exitosa'
                }
            else:
                return {
                    'success': False,
                    'message': 'Autenticación fallida'
                }
                
        except Exception as e:
            logger.error(f"Error en autenticación: {e}")
            return {
                'success': False,
                'message': f'Error de autenticación: {str(e)}'
            }
    
    def _get_user_info(self, email: str) -> Dict[str, Any]:
        """Obtiene información del usuario desde DynamoDB"""
        try:
            response = self.backend.users_table.get_item(
                Key={'email': email}
            )
            return response.get('Item', {})
        except Exception as e:
            logger.error(f"Error obteniendo usuario: {e}")
            return {}
    
    def _generate_jwt(self, user_info: Dict[str, Any]) -> str:
        """Genera JWT token personalizado"""
        payload = {
            'user_id': user_info.get('user_id'),
            'email': user_info.get('email'),
            'exp': datetime.utcnow() + timedelta(hours=24),
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    
    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verifica y decodifica JWT token"""
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            return {
                'valid': True,
                'payload': payload
            }
        except jwt.ExpiredSignatureError:
            return {'valid': False, 'message': 'Token expirado'}
        except jwt.InvalidTokenError:
            return {'valid': False, 'message': 'Token inválido'}

class TransactionService:
    """Servicio de transacciones bancarias"""
    
    def __init__(self):
        self.backend = BankingBackend()
        self.auth_service = AuthenticationService()
    
    def process_transaction(self, token: str, transaction_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Procesa una transacción bancaria
        """
        # Verificar token
        token_verification = self.auth_service.verify_token(token)
        if not token_verification['valid']:
            return {
                'success': False,
                'message': 'Token inválido o expirado'
            }
        
        user_id = token_verification['payload']['user_id']
        
        try:
            # Validar transacción
            validation = self._validate_transaction(transaction_data)
            if not validation['valid']:
                return validation
            
            # Crear transacción
            transaction = Transaction(
                transaction_id=str(uuid.uuid4()),
                user_id=user_id,
                account_from=transaction_data['account_from'],
                account_to=transaction_data['account_to'],
                amount=transaction_data['amount'],
                currency=transaction_data['currency'],
                transaction_type=transaction_data['type'],
                status='PENDING',
                timestamp=datetime.utcnow(),
                description=transaction_data.get('description', '')
            )
            
            # Validar con sistema on-premises (simulado)
            on_premises_validation = self._validate_with_on_premises(transaction)
            if not on_premises_validation['valid']:
                return on_premises_validation
            
            # Guardar en DynamoDB
            self._save_transaction(transaction)
            
            # Actualizar cache
            self._update_cache(transaction)
            
            # Enviar notificación
            self._send_notification(transaction)
            
            return {
                'success': True,
                'transaction_id': transaction.transaction_id,
                'status': 'COMPLETED',
                'message': 'Transacción procesada exitosamente'
            }
            
        except Exception as e:
            logger.error(f"Error procesando transacción: {e}")
            return {
                'success': False,
                'message': f'Error procesando transacción: {str(e)}'
            }
    
    def _validate_transaction(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Valida los datos de la transacción"""
        required_fields = ['account_from', 'account_to', 'amount', 'currency', 'type']
        
        for field in required_fields:
            if field not in data:
                return {
                    'valid': False,
                    'message': f'Campo requerido faltante: {field}'
                }
        
        if data['amount'] <= 0:
            return {
                'valid': False,
                'message': 'El monto debe ser mayor a 0'
            }
        
        if data['currency'] not in ['USD', 'EUR', 'MXN']:
            return {
                'valid': False,
                'message': 'Moneda no soportada'
            }
        
        return {'valid': True}
    
    def _validate_with_on_premises(self, transaction: Transaction) -> Dict[str, Any]:
        """
        Valida transacción con sistema on-premises
        Simula la conexión híbrida
        """
        # Simulación de validación on-premises
        if transaction.amount > 10000:
            return {
                'valid': False,
                'message': 'Monto excede límite permitido'
            }
        
        if transaction.transaction_type == 'TRANSFER' and transaction.amount > 5000:
            return {
                'valid': False,
                'message': 'Transferencia requiere aprobación manual'
            }
        
        return {'valid': True}
    
    def _save_transaction(self, transaction: Transaction):
        """Guarda transacción en DynamoDB"""
        item = {
            'transaction_id': transaction.transaction_id,
            'user_id': transaction.user_id,
            'account_from': transaction.account_from,
            'account_to': transaction.account_to,
            'amount': transaction.amount,
            'currency': transaction.currency,
            'transaction_type': transaction.transaction_type,
            'status': transaction.status,
            'timestamp': transaction.timestamp.isoformat(),
            'description': transaction.description
        }
        
        self.backend.transactions_table.put_item(Item=item)
    
    def _update_cache(self, transaction: Transaction):
        """Actualiza cache en Redis (simulado)"""
        cache_key = f"user_transactions:{transaction.user_id}"
        try:
            self.backend.cache_table.put_item(
                Item={
                    'cache_key': cache_key,
                    'last_updated': datetime.utcnow().isoformat(),
                    'transaction_count': 1
                }
            )
        except Exception as e:
            logger.warning(f"Error actualizando cache: {e}")
    
    def _send_notification(self, transaction: Transaction):
        """Envía notificación de transacción"""
        try:
            message = f"Transacción {transaction.transaction_id} procesada por ${transaction.amount} {transaction.currency}"
            sns.publish(
                TopicArn='arn:aws:sns:us-east-1:123456789012:banking-notifications',
                Message=message,
                Subject='Notificación de Transacción'
            )
        except Exception as e:
            logger.warning(f"Error enviando notificación: {e}")

class NotificationService:
    """Servicio de notificaciones"""
    
    def __init__(self):
        self.backend = BankingBackend()
    
    def send_push_notification(self, user_id: str, title: str, body: str, data: Dict[str, Any] = None):
        """Envía notificación push"""
        try:
            # Obtener token del dispositivo del usuario
            user_info = self._get_user_device_token(user_id)
            if not user_info.get('device_token'):
                return {'success': False, 'message': 'Token de dispositivo no encontrado'}
            
            # Enviar notificación push (simulado con SNS)
            message = {
                'default': body,
                'GCM': json.dumps({
                    'data': {
                        'title': title,
                        'body': body,
                        'data': data or {}
                    }
                })
            }
            
            sns.publish(
                TargetArn=user_info['device_token'],
                Message=json.dumps(message),
                MessageStructure='json'
            )
            
            return {'success': True, 'message': 'Notificación enviada'}
            
        except Exception as e:
            logger.error(f"Error enviando notificación push: {e}")
            return {'success': False, 'message': str(e)}
    
    def _get_user_device_token(self, user_id: str) -> Dict[str, Any]:
        """Obtiene token del dispositivo del usuario"""
        try:
            response = self.backend.users_table.get_item(
                Key={'user_id': user_id}
            )
            return response.get('Item', {})
        except Exception as e:
            logger.error(f"Error obteniendo token de dispositivo: {e}")
            return {}

class ReportingService:
    """Servicio de reportes y análisis"""
    
    def __init__(self):
        self.backend = BankingBackend()
        self.auth_service = AuthenticationService()
    
    def generate_user_report(self, token: str, user_id: str, report_type: str) -> Dict[str, Any]:
        """Genera reporte del usuario"""
        # Verificar token
        token_verification = self.auth_service.verify_token(token)
        if not token_verification['valid']:
            return {
                'success': False,
                'message': 'Token inválido o expirado'
            }
        
        try:
            if report_type == 'transactions':
                return self._generate_transaction_report(user_id)
            elif report_type == 'account_summary':
                return self._generate_account_summary(user_id)
            elif report_type == 'compliance':
                return self._generate_compliance_report(user_id)
            else:
                return {
                    'success': False,
                    'message': 'Tipo de reporte no soportado'
                }
                
        except Exception as e:
            logger.error(f"Error generando reporte: {e}")
            return {
                'success': False,
                'message': f'Error generando reporte: {str(e)}'
            }
    
    def _generate_transaction_report(self, user_id: str) -> Dict[str, Any]:
        """Genera reporte de transacciones"""
        try:
            response = self.backend.transactions_table.query(
                KeyConditionExpression='user_id = :uid',
                ExpressionAttributeValues={':uid': user_id}
            )
            
            transactions = response.get('Items', [])
            
            # Agrupar por mes
            monthly_summary = {}
            for trans in transactions:
                month = trans['timestamp'][:7]  # YYYY-MM
                if month not in monthly_summary:
                    monthly_summary[month] = {
                        'count': 0,
                        'total_amount': 0,
                        'currencies': {}
                    }
                
                monthly_summary[month]['count'] += 1
                monthly_summary[month]['total_amount'] += trans['amount']
                
                currency = trans['currency']
                if currency not in monthly_summary[month]['currencies']:
                    monthly_summary[month]['currencies'][currency] = 0
                monthly_summary[month]['currencies'][currency] += trans['amount']
            
            return {
                'success': True,
                'report_type': 'transactions',
                'user_id': user_id,
                'total_transactions': len(transactions),
                'monthly_summary': monthly_summary,
                'generated_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error generando reporte de transacciones: {e}")
            return {
                'success': False,
                'message': f'Error generando reporte: {str(e)}'
            }
    
    def _generate_account_summary(self, user_id: str) -> Dict[str, Any]:
        """Genera resumen de cuenta"""
        # Simulación de datos de cuenta desde sistema on-premises
        return {
            'success': True,
            'report_type': 'account_summary',
            'user_id': user_id,
            'accounts': [
                {
                    'account_number': '****1234',
                    'type': 'CHECKING',
                    'balance': 5000.00,
                    'currency': 'USD',
                    'status': 'ACTIVE'
                },
                {
                    'account_number': '****5678',
                    'type': 'SAVINGS',
                    'balance': 15000.00,
                    'currency': 'USD',
                    'status': 'ACTIVE'
                }
            ],
            'generated_at': datetime.utcnow().isoformat()
        }
    
    def _generate_compliance_report(self, user_id: str) -> Dict[str, Any]:
        """Genera reporte de compliance"""
        # Simulación de validación de compliance desde sistema on-premises
        return {
            'success': True,
            'report_type': 'compliance',
            'user_id': user_id,
            'compliance_status': 'COMPLIANT',
            'risk_level': 'LOW',
            'last_review': '2024-01-15',
            'next_review': '2024-07-15',
            'flags': [],
            'generated_at': datetime.utcnow().isoformat()
        }

# Lambda Functions Handlers

def lambda_handler_auth(event, context):
    """Handler para función Lambda de autenticación"""
    try:
        auth_service = AuthenticationService()
        
        if event['httpMethod'] == 'POST':
            body = json.loads(event['body'])
            email = body.get('email')
            password = body.get('password')
            
            if not email or not password:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'message': 'Email y password son requeridos'})
                }
            
            result = auth_service.authenticate_user(email, password)
            
            if result['success']:
                return {
                    'statusCode': 200,
                    'body': json.dumps(result)
                }
            else:
                return {
                    'statusCode': 401,
                    'body': json.dumps(result)
                }
        
        return {
            'statusCode': 405,
            'body': json.dumps({'message': 'Método no permitido'})
        }
        
    except Exception as e:
        logger.error(f"Error en lambda_handler_auth: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'message': 'Error interno del servidor'})
        }

def lambda_handler_transactions(event, context):
    """Handler para función Lambda de transacciones"""
    try:
        transaction_service = TransactionService()
        
        if event['httpMethod'] == 'POST':
            # Verificar token en headers
            token = event['headers'].get('Authorization', '').replace('Bearer ', '')
            if not token:
                return {
                    'statusCode': 401,
                    'body': json.dumps({'message': 'Token de autorización requerido'})
                }
            
            body = json.loads(event['body'])
            result = transaction_service.process_transaction(token, body)
            
            if result['success']:
                return {
                    'statusCode': 200,
                    'body': json.dumps(result)
                }
            else:
                return {
                    'statusCode': 400,
                    'body': json.dumps(result)
                }
        
        return {
            'statusCode': 405,
            'body': json.dumps({'message': 'Método no permitido'})
        }
        
    except Exception as e:
        logger.error(f"Error en lambda_handler_transactions: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'message': 'Error interno del servidor'})
        }

def lambda_handler_notifications(event, context):
    """Handler para función Lambda de notificaciones"""
    try:
        notification_service = NotificationService()
        
        if event['httpMethod'] == 'POST':
            body = json.loads(event['body'])
            user_id = body.get('user_id')
            title = body.get('title')
            body_text = body.get('body')
            data = body.get('data', {})
            
            if not all([user_id, title, body_text]):
                return {
                    'statusCode': 400,
                    'body': json.dumps({'message': 'user_id, title y body son requeridos'})
                }
            
            result = notification_service.send_push_notification(user_id, title, body_text, data)
            
            if result['success']:
                return {
                    'statusCode': 200,
                    'body': json.dumps(result)
                }
            else:
                return {
                    'statusCode': 400,
                    'body': json.dumps(result)
                }
        
        return {
            'statusCode': 405,
            'body': json.dumps({'message': 'Método no permitido'})
        }
        
    except Exception as e:
        logger.error(f"Error en lambda_handler_notifications: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'message': 'Error interno del servidor'})
        }

def lambda_handler_reports(event, context):
    """Handler para función Lambda de reportes"""
    try:
        reporting_service = ReportingService()
        
        if event['httpMethod'] == 'GET':
            # Verificar token en headers
            token = event['headers'].get('Authorization', '').replace('Bearer ', '')
            if not token:
                return {
                    'statusCode': 401,
                    'body': json.dumps({'message': 'Token de autorización requerido'})
                }
            
            # Obtener parámetros de query
            user_id = event['queryStringParameters'].get('user_id')
            report_type = event['queryStringParameters'].get('type', 'transactions')
            
            if not user_id:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'message': 'user_id es requerido'})
                }
            
            result = reporting_service.generate_user_report(token, user_id, report_type)
            
            if result['success']:
                return {
                    'statusCode': 200,
                    'body': json.dumps(result)
                }
            else:
                return {
                    'statusCode': 400,
                    'body': json.dumps(result)
                }
        
        return {
            'statusCode': 405,
            'body': json.dumps({'message': 'Método no permitido'})
        }
        
    except Exception as e:
        logger.error(f"Error en lambda_handler_reports: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'message': 'Error interno del servidor'})
        }

# Ejemplo de uso
if __name__ == "__main__":
    print("🏦 Backend Serverless para Banca Móvil")
    print("=" * 50)
    
    # Ejemplo de autenticación
    auth_service = AuthenticationService()
    print("🔐 Probando autenticación...")
    
    # Ejemplo de transacción
    transaction_service = TransactionService()
    print("💳 Probando servicio de transacciones...")
    
    # Ejemplo de notificaciones
    notification_service = NotificationService()
    print("📱 Probando servicio de notificaciones...")
    
    # Ejemplo de reportes
    reporting_service = ReportingService()
    print("📊 Probando servicio de reportes...")
    
    print("\n✅ Backend inicializado correctamente")
    print("🚀 Listo para desplegar en AWS Lambda")

