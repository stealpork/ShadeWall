import streamlit as st
import pandas as pd
import plotly.express as px
import json
import os
import subprocess
import time

st.set_page_config(page_title="ShadeWall Dashboard", layout="wide", page_icon="🛡️")

st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    .stMetric { background-color: #161b22; padding: 15px; border-radius: 10px; border: 1px solid #30363d; }
    </style>
    """, unsafe_allow_html=True)

def clear_all_data():
    if os.path.exists("shadewall_log.json"):
        with open('shadewall_log.json', "w") as f:
            f.write("")
    st.cache_data.clear()
    st.success("Логи очищены!")
    
def system_unban():
    subprocess.run(["sudo", "iptables", "-F", "SHADEWALL"])

st.sidebar.title("🛠️ Управление IPS")

st.sidebar.subheader("🏳️ Белый список (IP)")
if os.path.exists("whitelist.txt"):
    with open("whitelist.txt", "r") as f:
        current_whitelist = f.read()
else:
    current_whitelist = ""

new_whitelist = st.sidebar.text_area("Список IP (через запятую или с новой строки):", current_whitelist, height=150)
if st.sidebar.button("✅ Применить White-list"):
    with open("whitelist.txt", "w") as f:
        f.write(new_whitelist)
    current_list = new_whitelist
    for ip in current_list:
        check = subprocess.run(f"sudo iptables -C SHADEWALL -s {ip} -j ACCEPT", 
                            shell=True, capture_output=True)
        if check.returncode != 0:
            subprocess.run(["sudo", "iptables", "-I", "SHADEWALL", "1", "-s", ip, "-j", "ACCEPT"])
    st.sidebar.success("Список обновлен!")

st.sidebar.markdown("---")

if st.sidebar.button("🔥 Сбросить все БАНЫ", use_container_width=True):
    system_unban()
    st.sidebar.success("iptables очищен!")

if st.sidebar.button("🗑️ Очистить логи и карту", use_container_width=True):
    clear_all_data()
    st.sidebar.warning("Данные удалены!")

def load_data():
    file_path = "shadewall_log.json"
    if not os.path.exists(file_path) or os.stat(file_path).st_size == 0:
        return pd.DataFrame()
    
    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
        data = [json.loads(l) for l in lines if l.strip()]
    return pd.DataFrame(data)

df = load_data()

st.title("🛡️ ShadeWall: Мониторинг безопасности")

if not df.empty:
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Всего инцидентов", len(df))
    m2.metric("Уникальных IP", df['ip'].nunique())
    m3.metric("DoS атак", len(df[df['reason'].str.contains("DoS", na=False)]))
    m4.metric("Honeypot хитов", len(df[df['reason'].str.contains("Honey", na=False)]))
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📊 Типы угроз")
        reason_counts = df['reason'].value_counts().reset_index()
        reason_counts.columns = ['Причина', 'Количество']
        fig = px.bar(reason_counts, x='Количество', y='Причина', orientation='h', 
                     color='Количество', color_continuous_scale='Reds')
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("🎯 Целевые порты")
        port_counts = df['port'].value_counts().reset_index()
        port_counts.columns = ['Порт', 'Количество']
        fig2 = px.pie(port_counts, values='Количество', names='Порт', hole=0.3)
        st.plotly_chart(fig2, use_container_width=True)

    st.subheader("📝 Журнал последних событий")
    st.dataframe(df.sort_values(by='time', ascending=False), use_container_width=True)

else:
    st.info("📡 Ожидание данных... Запустите атаку (hping3 или nmap) для теста.")

time.sleep(2)
st.rerun()