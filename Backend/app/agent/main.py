"""Canonical entry point for the existing agent daemon."""

from agent.agent import ImmuneAgent, agent_health_app

__all__ = ["ImmuneAgent", "agent_health_app"]
