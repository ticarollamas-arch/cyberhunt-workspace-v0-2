// Deliberately limited, local, line-based defensive review. No network or execution.
export const rules=[
{id:'CWE-22',name:'Revisar construção de caminhos',pattern:/\b(?:path\.join|os\.path\.join|Path)\s*\(/,advice:'Verifique contenção no diretório autorizado, normalização e links simbólicos; use testes locais.'},
{id:'CWE-89',name:'Revisar construção de consultas',pattern:/\b(?:execute|query)\s*\(\s*(?:f["']|`|[^,)]*\+)/,advice:'Prefira consultas parametrizadas e valide o contrato do driver.'},
{id:'CWE-79',name:'Revisar saída HTML',pattern:/\.innerHTML\s*=|dangerouslySetInnerHTML/,advice:'Prefira textContent ou mecanismos de escape contextual do framework.'},
{id:'CWE-95',name:'Revisar avaliação dinâmica',pattern:/\b(?:eval|exec)\s*\(/,advice:'Substitua avaliação dinâmica por operações explícitas e dados estruturados.'},
{id:'CWE-798',name:'Possível segredo literal',pattern:/\b(?:password|api[_-]?key|secret)\s*[:=]\s*["'][^"']{8,}["']/i,advice:'Revise se é fixture; use gestão de segredos e não publique credenciais.'},
{id:'CWE-120',name:'Revisar cópia de memória',pattern:/\b(?:strcpy|strcat|gets|sprintf)\s*\(/,advice:'Revise limites e contratos de tamanho; prefira abstrações seguras e testes com sanitizadores.'},
{id:'CWE-327',name:'Revisar algoritmo criptográfico',pattern:/\b(?:md5|sha1)\s*\(/i,advice:'Verifique a finalidade; para segurança use algoritmos apropriados e bibliotecas mantidas.'}];
export function scan(code){return code.split(/\r?\n/).flatMap((line,i)=>rules.filter(r=>r.pattern.test(line)).map(({id,name,advice})=>({id,name,advice,line:i+1})));}
