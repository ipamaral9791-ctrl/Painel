#!/usr/bin/env python3
"""Robô de vendas do Painel Gerencial (roda no GitHub Actions, sem o PC do Igor ligado).

Lê o painel público do Vitrúvio, mapeia cada unidade para a concessionária do dashboard e grava vendas.json,
CRIPTOGRAFADO com a mesma senha e o mesmo sal do painel (painel.json). O log é público: só imprime contagens, nunca valores.
"""
import base64, hashlib, hmac, html, json, os, re, subprocess, sys, unicodedata
from datetime import datetime
from zoneinfo import ZoneInfo
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

URL = os.environ.get('VITRUVIO_URL', '')
SENHA = os.environ.get('PAINEL_SENHA', '')
if not URL or not SENHA:
    sys.exit('Faltam os segredos VITRUVIO_URL e/ou PAINEL_SENHA.')


def norm(s):
    s = unicodedata.normalize('NFD', s)
    s = ''.join(c for c in s if unicodedata.category(c) != 'Mn')
    return re.sub(r'[^A-Z0-9]', '', s.upper())


# nome da unidade no Vitrúvio (sem o código final) -> nome da concessionária no dashboard
MAPA = {
    'ABSOLUTA - BAIXADA': 'ABSOLUTA BAIXADA', 'ABSOLUTA - IMIRIM': 'ABSOLUTA IMIRIM', 'AMANTINI': 'AMANTINNI',
    'COTAC': 'COTAC', 'GRACIANO': 'GRACIANO', 'GUIAUTO': 'GUIAUTO', 'LAGOA NORTE': 'LAGOA NORTE', 'MARKA': 'MARKA',
    'MCV': 'MCV VALADARES', 'PEDRAGON DF': 'PEDRAGON BANDEIRANTES', 'NOVA SP': 'NOVA', 'PRIMARCA SP': 'PRIMARCA',
    'SIMCAUTO': 'SIMCAUTO', 'TAUBATÉ': 'TAUBATÉ', 'VESSA - VILA VELHA': 'VESSA- VILA VELHA',
}
MAPAN = {norm(k): v for k, v in MAPA.items()}
MESES = ['Jan', 'Fev', 'Mar', 'Abr', 'Mai', 'Jun', 'Jul', 'Ago', 'Set', 'Out', 'Nov', 'Dez']


def to_num(s):
    s = re.sub(r'[^\d,.\-]', '', s or '')
    if ',' in s:
        s = s.replace('.', '').replace(',', '.')
    elif re.fullmatch(r'-?\d{1,3}(\.\d{3})+', s):
        s = s.replace('.', '')
    try:
        return float(s)
    except ValueError:
        return None


def ler_painel():
    for tent in range(1, 4):
        try:
            r = subprocess.run(['google-chrome', '--headless=new', '--no-sandbox', '--disable-gpu', '--virtual-time-budget=20000',
                                '--dump-dom', URL], capture_output=True, text=True, timeout=150)
            dom = r.stdout
        except subprocess.TimeoutExpired:
            dom = ''
        unidades, total, dia = {}, None, None
        for tr in re.findall(r'(?s)<tr[^>]*>(.*?)</tr>', dom):
            cel = [re.sub(r'\s+', ' ', html.unescape(re.sub(r'<[^>]+>', '', c))).strip()
                   for c in re.findall(r'(?s)<t[dh][^>]*>(.*?)</t[dh]>', tr)]
            if len(cel) >= 3 and re.match(r'^VENDAS\s*DO\s*DIA', cel[1]):
                dia = to_num(cel[2])
            if len(cel) >= 5:
                m = re.match(r'^\d+\s*\|\s*(.+?)\s*[-–]\s*[0-9A-Z]{3}$', cel[0])
                if m:
                    unidades[norm(m.group(1))] = {'cotas': to_num(cel[2]), 'credito': to_num(cel[3])}
                elif cel[0] == 'TOTAL':
                    total = {'cotas': to_num(cel[2]), 'credito': to_num(cel[3])}
        print(f'tentativa {tent}: {len(unidades)} unidades no painel; TOTAL: {total is not None}')
        if len(unidades) >= 10 and total:
            return unidades, total, dia
    sys.exit('Leitura insuficiente do painel do Vitruvio (menos de 10 unidades).')


def derivar(salt, iteracoes):
    bits = hashlib.pbkdf2_hmac('sha256', SENHA.encode('utf-8'), salt, iteracoes, 64)
    return bits[:32], bits[32:]


def cifrar(obj, salt, iteracoes):
    ak, mk = derivar(salt, iteracoes)
    iv = os.urandom(16)
    pad = padding.PKCS7(128).padder()
    dados = pad.update(json.dumps(obj, ensure_ascii=False, separators=(',', ':')).encode('utf-8')) + pad.finalize()
    enc = Cipher(algorithms.AES(ak), modes.CBC(iv)).encryptor()
    ct = enc.update(dados) + enc.finalize()
    mac = hmac.new(mk, iv + ct, hashlib.sha256).digest()
    b = lambda x: base64.b64encode(x).decode()
    return {'salt': b(salt), 'iv': b(iv), 'ct': b(ct), 'mac': b(mac), 'iter': iteracoes}


def decifrar(P):
    salt, iv, ct, mac = (base64.b64decode(P[k]) for k in ('salt', 'iv', 'ct', 'mac'))
    ak, mk = derivar(salt, int(P['iter']))
    if not hmac.compare_digest(hmac.new(mk, iv + ct, hashlib.sha256).digest(), mac):
        return None
    dec = Cipher(algorithms.AES(ak), modes.CBC(iv)).decryptor()
    pad = padding.PKCS7(128).unpadder()
    return json.loads((pad.update(dec.update(ct) + dec.finalize()) + pad.finalize()).decode('utf-8'))


def main():
    # sal e iterações do painel principal (públicos): a mesma chave abre painel.json e vendas.json
    try:
        P = json.load(open('painel.json', encoding='utf-8'))
        salt, iteracoes = base64.b64decode(P['salt']), int(P['iter'])
    except Exception as e:
        sys.exit(f'painel.json indisponível para obter o sal ({type(e).__name__}).')

    unidades, total, dia = ler_painel()
    mapeadas = {MAPAN[k]: v for k, v in unidades.items() if k in MAPAN and v['cotas'] is not None and v['credito'] is not None}
    print(f'unidades mapeadas para o dashboard: {len(mapeadas)}')
    if len(mapeadas) < 10:
        sys.exit('Mapeamento insuficiente (menos de 10 concessionárias).')

    agora = datetime.now(ZoneInfo('America/Sao_Paulo'))
    obj = {'lido': agora.strftime('%Y-%m-%d %H:%M'), 'mes': f'{MESES[agora.month - 1]}/{agora:%y}', 'n': len(unidades),
           'total': total, 'dia': dia, 'unidades': mapeadas}

    # nada mudou desde a última leitura? então não grava (evita commits à toa)
    if os.path.exists('vendas.json'):
        try:
            ant = decifrar(json.load(open('vendas.json', encoding='utf-8')))
            if ant and ant.get('mes') == obj['mes'] and ant.get('total') == total and ant.get('dia') == dia and ant.get('unidades') == mapeadas:
                print('Sem mudança nas vendas; vendas.json mantido.')
                return
        except Exception:
            pass
    json.dump(cifrar(obj, salt, iteracoes), open('vendas.json', 'w', encoding='utf-8'))
    print(f"vendas.json atualizado ({len(mapeadas)} concessionárias, mês {obj['mes']}).")


main()
