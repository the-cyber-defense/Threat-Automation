import pandas as pd
import matplotlib.pyplot as plt
import streamlit as st
from datetime import datetime, timedelta
import json
import os

def pay_down_debt_with_schedule(debts, base_budget, method="avalanche", min_payment_rate=0.02, raise_month=None, raise_amount=0, min_payment_override=None, due_date_offset=0, custom_payments=None):
    import copy

    if method == "avalanche":
        debts = sorted(copy.deepcopy(debts), key=lambda x: -x["apr"])
    elif method == "snowball":
        debts = sorted(copy.deepcopy(debts), key=lambda x: x["balance"])

    month = 0
    history = []
    total_interest = 0
    total_min_payments = 0
    schedule = []

    while any(debt["balance"] > 0.01 for debt in debts):
        month += 1
        monthly_budget = custom_payments[month - 1] if custom_payments and month - 1 < len(custom_payments) else base_budget + (raise_amount if raise_month and month >= raise_month else 0)
        balances = {"Month": month}
        payments = {"Month": month}
        monthly_interest = 0
        monthly_min = 0

        for debt in debts:
            if debt["balance"] > 0:
                interest = (debt["apr"] / 100) * (1 / 365) * 30 * (1 + due_date_offset / 30) * debt["balance"]
                debt["balance"] += interest
                monthly_interest += interest

        total_interest += monthly_interest

        for debt in debts:
            if debt["balance"] > 0:
                min_payment = max(debt["balance"] * (min_payment_override if min_payment_override is not None else min_payment_rate), 25)
                payment = min(min_payment, debt["balance"])
                debt["balance"] -= payment
                monthly_budget -= payment
                monthly_min += payment
                payments[debt["name"]] = round(payment, 2)
            else:
                payments[debt["name"]] = 0.0

        total_min_payments += monthly_min

        for debt in debts:
            if debt["balance"] > 0 and monthly_budget > 0:
                payment = min(monthly_budget, debt["balance"])
                debt["balance"] -= payment
                monthly_budget -= payment
                payments[debt["name"]] += round(payment, 2)

        for debt in debts:
            balances[debt["name"]] = round(debt["balance"], 2)

        balances["Interest Paid"] = round(total_interest, 2)
        balances["Minimums Paid"] = round(total_min_payments, 2)
        balances["Monthly Interest"] = round(monthly_interest, 2)
        balances["Monthly Minimum"] = round(monthly_min, 2)
        history.append(balances)
        schedule.append(payments)

    df_balances = pd.DataFrame(history)
    df_schedule = pd.DataFrame(schedule)
    return df_balances, df_schedule, total_interest, total_min_payments, month

# Streamlit App
st.title("📉 Credit Card Debt Payoff Simulator")

st.markdown("### 💵 Monthly Budget")
user_monthly_income = st.number_input("Enter Your Monthly Income ($)", min_value=0, value=4000, step=100)

# Load user profile
profiles_dir = "profiles"
os.makedirs(profiles_dir, exist_ok=True)
profile_names = [f[:-5] for f in os.listdir(profiles_dir) if f.endswith(".json")]
selected_profile = st.selectbox("Load Existing Profile or Create New", ["Create New..."] + profile_names)

if selected_profile == "Create New...":
    new_profile_name = st.text_input("Enter New Profile Name")
    use_profile = st.button("Start with Blank Profile")
    user_debts = []
else:
    with open(os.path.join(profiles_dir, f"{selected_profile}.json")) as f:
        user_debts = json.load(f)
    use_profile = True

if use_profile:
    st.markdown("### 💳 Edit Credit Card Details")
    for debt in user_debts:
        col1, col2 = st.columns(2)
        with col1:
            debt["balance"] = st.number_input(f"{debt['name']} Balance ($)", min_value=0.0, value=debt["balance"], step=50.0, key=f"bal_{debt['name']}")
        with col2:
            debt["apr"] = st.number_input(f"{debt['name']} APR (%)", min_value=0.0, max_value=50.0, value=debt["apr"], step=0.25, key=f"apr_{debt['name']}")
else:
    default_names = ["Redwood CU Personal", "Amex Business", "Apple Card", "Venmo", "Capital One"]
    user_debts = []
    for name in default_names:
        col1, col2 = st.columns(2)
        with col1:
            balance = st.number_input(f"{name} Balance ($)", min_value=0.0, value=1000.0, step=50.0, key=f"bal_{name}")
        with col2:
            apr = st.number_input(f"{name} APR (%)", min_value=0.0, max_value=50.0, value=20.0, step=0.25, key=f"apr_{name}")
        user_debts.append({"name": name, "balance": balance, "apr": apr})


if st.button("💾 Save Profile") and selected_profile == "Create New..." and new_profile_name:
    with open(os.path.join(profiles_dir, f"{new_profile_name}.json"), "w") as f:
        json.dump(user_debts, f)
    st.success(f"Saved profile as {new_profile_name}!")

if user_debts:
    custom_payment_mode = st.checkbox("Use Custom Monthly Payments")
    custom_payments = []
    if custom_payment_mode:
        num_months = st.number_input("How many months of payments?", min_value=1, value=12, step=1)
        for i in range(num_months):
            custom_payment = st.number_input(f"Month {i+1} Payment ($)", min_value=0, value=1000, step=50, key=f"month_{i+1}_pay")
            custom_payments.append(custom_payment)

    min_rate_input = st.slider("Minimum Payment Rate (%)", 1, 10, 2) / 100
    due_date_offset = st.slider("Due Date Offset (days late)", 0, 30, 0)
    default_payment = min(user_monthly_income, 1000)
    monthly_budget = st.slider("Starting Monthly Payment ($)", 100, int(user_monthly_income), default_payment, 50)

    # Budget allocation visualization
    st.subheader("📊 Budget Allocation Overview")
    budget_df = pd.DataFrame({
        "Amount": [monthly_budget, user_monthly_income - monthly_budget]
    }, index=["Debt Payment", "Remaining Income"])
    st.bar_chart(budget_df)

    show_pie = st.checkbox("Show as Percentage & Pie Chart")
    if show_pie:
        percent_debt = (monthly_budget / user_monthly_income) * 100 if user_monthly_income > 0 else 0
        percent_remaining = 100 - percent_debt
        st.markdown(f"**Debt Payment:** {percent_debt:.1f}%  \n**Remaining Income:** {percent_remaining:.1f}%")
        
        pie_data = pd.Series([percent_debt, percent_remaining], index=["Debt Payment", "Remaining Income"])
        st.pyplot(pie_data.plot.pie(autopct='%1.1f%%', figsize=(5, 5), ylabel=""))

    col3, col4 = st.columns(2)
    with col3:
        raise_month = st.number_input("Increase Payment Starting Month", min_value=1, value=6, step=1)
    with col4:
        raise_amount = st.number_input("Increase Amount ($)", min_value=0, value=0, step=50)

    df_ava, schedule_ava, int_ava, min_ava, mon_ava = pay_down_debt_with_schedule(user_debts, monthly_budget, "avalanche", min_payment_override=min_rate_input, due_date_offset=due_date_offset, custom_payments=custom_payments if custom_payment_mode else None)
    df_snow, schedule_snow, int_snow, min_snow, mon_snow = pay_down_debt_with_schedule(user_debts, monthly_budget, "snowball", min_payment_override=min_rate_input, due_date_offset=due_date_offset, custom_payments=custom_payments if custom_payment_mode else None)

    payoff_date_ava = datetime.today() + timedelta(days=30 * mon_ava)
    payoff_date_snow = datetime.today() + timedelta(days=30 * mon_snow)

    st.subheader("📋 Strategy Comparison Summary")
    col5, col6 = st.columns(2)
    with col5:
        st.markdown("**Avalanche Method**")
        st.markdown(f"""
- Months: `{mon_ava}`
- Payoff: `{payoff_date_ava.strftime('%B %Y')}`
- Interest Paid: `${int_ava:,.2f}`
- Minimums Paid: `${min_ava:,.2f}`
""")
    with col6:
        st.markdown("**Snowball Method**")
        st.markdown(f"""
- Months: `{mon_snow}`
- Payoff: `{payoff_date_snow.strftime('%B %Y')}`
- Interest Paid: `${int_snow:,.2f}`
- Minimums Paid: `${min_snow:,.2f}`
""")

    st.subheader("📊 Avalanche Payment Schedule")
    st.dataframe(schedule_ava, use_container_width=True)

    st.subheader("📊 Snowball Payment Schedule")
    st.dataframe(schedule_snow, use_container_width=True)

    st.subheader("📈 Debt Payoff Timeline Comparison")
    fig, ax = plt.subplots()
    for column in df_ava.columns[1:-4]:
        ax.plot(df_ava["Month"], df_ava[column], label=f"Ava: {column}", linestyle="--")
        ax.plot(df_snow["Month"], df_snow[column], label=f"Snow: {column}", linestyle="-")
    ax.set_xlabel("Month")
    ax.set_ylabel("Balance ($)")
    ax.set_title("Avalanche vs Snowball Debt Payoff")
    ax.legend()
    st.pyplot(fig)

    st.subheader("📊 Cumulative Interest & Minimum Payments")
    fig2, ax2 = plt.subplots()
    ax2.plot(df_ava["Month"], df_ava["Interest Paid"], label="Ava: Interest", linestyle="--")
    ax2.plot(df_snow["Month"], df_snow["Interest Paid"], label="Snow: Interest", linestyle="-")
    ax2.plot(df_ava["Month"], df_ava["Minimums Paid"], label="Ava: Minimums", linestyle="--")
    ax2.plot(df_snow["Month"], df_snow["Minimums Paid"], label="Snow: Minimums", linestyle="-")
    ax2.set_xlabel("Month")
    ax2.set_ylabel("Cumulative ($)")
    ax2.set_title("Interest and Minimum Payments Over Time")
    ax2.legend()
    st.pyplot(fig2)

    st.subheader("📥 Export CSV")
    tab1, tab2 = st.tabs(["Avalanche CSV", "Snowball CSV"])
    with tab1:
        st.download_button("Download Avalanche Schedule", data=df_ava.to_csv(index=False).encode("utf-8"), file_name="avalanche_balances.csv", mime="text/csv")
        st.download_button("Download Avalanche Payments", data=schedule_ava.to_csv(index=False).encode("utf-8"), file_name="avalanche_payments.csv", mime="text/csv")
    with tab2:
        st.download_button("Download Snowball Schedule", data=df_snow.to_csv(index=False).encode("utf-8"), file_name="snowball_balances.csv", mime="text/csv")
        st.download_button("Download Snowball Payments", data=schedule_snow.to_csv(index=False).encode("utf-8"), file_name="snowball_payments.csv", mime="text/csv")
