import requests

URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

def baixar_dados():
    print("[*] Baixando dados do MITRE ATT&CK...")
    response = requests.get(URL)
    response.raise_for_status()
    print("[+] Download concluído.")
    return response.json()

def construir_mapeamento_com_subtecnicas(dados):
    mapeamento = {}

    tecnicas_por_id = {}
    subtecnicas_por_pai = {}

    for obj in dados.get("objects", []):
        if obj.get("type") == "attack-pattern" and "kill_chain_phases" in obj:
            external_refs = obj.get("external_references", [])
            mitre_ref = next((ref for ref in external_refs if ref.get("source_name") == "mitre-attack"), {})
            tecnica_id = mitre_ref.get("external_id", "SEM_ID")
            nome = obj.get("name", "SEM_NOME")
            kill_phases = [k["phase_name"] for k in obj.get("kill_chain_phases", [])]

            tecnica = {
                "id": tecnica_id,
                "nome": nome,
                "full": f"{tecnica_id} | {nome}",
                "kill_chain_phases": kill_phases,
                "is_sub": "." in tecnica_id,
                "id_pai": tecnica_id.split(".")[0] if "." in tecnica_id else None
            }

            if tecnica["is_sub"]:
                subtecnicas_por_pai.setdefault(tecnica["id_pai"], []).append(tecnica)
            else:
                tecnicas_por_id[tecnica_id] = tecnica

    for tecnica_id, tecnica in tecnicas_por_id.items():
        for fase in tecnica["kill_chain_phases"]:
            if fase not in mapeamento:
                mapeamento[fase] = {}
            mapeamento[fase][tecnica_id] = {
                "nome": tecnica["nome"],
                "full": tecnica["full"],
                "subtecnicas": subtecnicas_por_pai.get(tecnica_id, [])
            }

    return mapeamento

def imprimir_mapeamento(mapeamento):
    for tatica, tecnicas in sorted(mapeamento.items()):
        print(f"\n🎯 Tática: {tatica}")
        for tid, dados in sorted(tecnicas.items()):
            sub = dados["subtecnicas"]
            if sub:
                print(f"   └─ {dados['full']} ({len(sub)} sub-técnicas)")
                for s in sorted(sub, key=lambda x: x['id']):
                    print(f"       ├─ {s['full']}")
            else:
                print(f"   └─ {dados['full']}")

if __name__ == "__main__":
    try:
        dados = baixar_dados()
        mapeamento = construir_mapeamento_com_subtecnicas(dados)
        imprimir_mapeamento(mapeamento)
    except Exception as e:
        print(f"[ERRO] {e}")
