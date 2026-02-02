#!/bin/bash
from flask import Flask, render_template, request, redirect, url_for
from models import db, Ticket
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tickets.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

with app.app_context():
    db.create_all()

TECHNICIANS = [
    "Alex Johnson",
    "Jordan Lee",
    "Maria Gomez",
    "Chris Walker"
]

@app.route("/")
def index():
    status_filter = request.args.get("status", "All")
    priority_filter = request.args.get("priority", "All")

    tickets = Ticket.query

    if status_filter != "All":
        tickets = tickets.filter_by(status=status_filter)

    if priority_filter != "All":
        tickets = tickets.filter_by(priority=priority_filter)

    tickets = tickets.order_by(Ticket.created_at.desc()).all()

    return render_template("index.html",
                           tickets=tickets,
                           status_filter=status_filter,
                           priority_filter=priority_filter)

@app.route("/create", methods=["GET", "POST"])
def create_ticket():
    if request.method == "POST":
        title = request.form["title"]
        description = request.form["description"]
        priority = request.form["priority"]
        category = request.form["category"]
        assigned_to = request.form["assigned_to"]

        ticket = Ticket(title=title,
                        description=description,
                        priority=priority,
                        category=category,
                        assigned_to=assigned_to)

        db.session.add(ticket)
        db.session.commit()

        return redirect(url_for("index"))

    return render_template("create_ticket.html", technicians=TECHNICIANS)

@app.route("/ticket/<int:ticket_id>", methods=["GET", "POST"])
def view_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)

    if request.method == "POST":
        ticket.status = request.form["status"]
        ticket.assigned_to = request.form["assigned_to"]

        new_note = request.form["note"]
        if new_note.strip():
            ticket.notes += f"\n[{datetime.utcnow()}] {new_note}"

        db.session.commit()

    return render_template("view_ticket.html", ticket=ticket, technicians=TECHNICIANS)

if __name__ == "__main__":
    app.run(debug=True)
