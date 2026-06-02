from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Any, Optional


@dataclass
class EvidenceItem:
    type: str
    location: str
    reason: str
    confidence: float
    code_snippet: Optional[str] = None


@dataclass
class AgentResult:
    agent_name: str
    signal_type: str
    confidence: float
    evidence: List[EvidenceItem]
    recommendation: str
    findings: List[Dict]
    metadata: Dict[str, Any]
    timestamp: datetime
    processing_time: float


@dataclass
class CrossAgentMessage:
    from_agent: str
    to_agent: Optional[str]
    message_type: str
    content: Dict
    signal_id: Optional[str] = None


@dataclass
class Conflict:
    signal_id: str
    agent_a: str
    agent_b: str
    type: str
    details: Dict[str, Any]


@dataclass
class ConsensusResult:
    agreed_signals: List[str]
    disputed_signals: List[str]
    average_confidence: float
    consensus_level: str


@dataclass
class AggregatedResult:
    total_signals: int
    by_agent: Dict[str, int]
    by_signal_type: Dict[str, int]
    high_confidence_signals: List[str]
    recommendations: List[str]
    conflicts: List[Conflict]


class AgentResultAggregator:

    @staticmethod
    def aggregate(results: List[AgentResult]) -> AggregatedResult:
        by_agent: Dict[str, int] = {}
        by_signal_type: Dict[str, int] = {}
        high_confidence_signals: List[str] = []
        recommendations: List[str] = []
        all_signals: List[str] = []

        for result in results:
            by_agent[result.agent_name] = by_agent.get(result.agent_name, 0) + 1
            by_signal_type[result.signal_type] = by_signal_type.get(result.signal_type, 0) + 1

            for finding in result.findings:
                signal_id = finding.get('signal_id', '')
                if signal_id and signal_id not in all_signals:
                    all_signals.append(signal_id)
                if finding.get('confidence', 0) >= 0.7 and signal_id:
                    high_confidence_signals.append(signal_id)

            if result.recommendation and result.recommendation not in recommendations:
                recommendations.append(result.recommendation)

        return AggregatedResult(
            total_signals=len(all_signals),
            by_agent=by_agent,
            by_signal_type=by_signal_type,
            high_confidence_signals=high_confidence_signals,
            recommendations=recommendations,
            conflicts=[]
        )

    @staticmethod
    def detect_conflicts(results: List[AgentResult]) -> List[Conflict]:
        conflicts: List[Conflict] = []
        signal_map: Dict[str, List[tuple]] = {}

        for result in results:
            for finding in result.findings:
                signal_id = finding.get('signal_id', '')
                if not signal_id:
                    continue
                if signal_id not in signal_map:
                    signal_map[signal_id] = []
                signal_map[signal_id].append((result.agent_name, finding))

        for signal_id, entries in signal_map.items():
            if len(entries) < 2:
                continue

            for i in range(len(entries)):
                for j in range(i + 1, len(entries)):
                    agent_a, finding_a = entries[i]
                    agent_b, finding_b = entries[j]

                    state_a = finding_a.get('signal_state', '')
                    state_b = finding_b.get('signal_state', '')
                    if state_a != state_b:
                        conflicts.append(Conflict(
                            signal_id=signal_id,
                            agent_a=agent_a,
                            agent_b=agent_b,
                            type='state_conflict',
                            details={
                                'state_a': state_a,
                                'state_b': state_b,
                                'finding_a': finding_a,
                                'finding_b': finding_b
                            }
                        ))

                    conf_a = finding_a.get('confidence', 0)
                    conf_b = finding_b.get('confidence', 0)
                    if abs(conf_a - conf_b) > 0.3:
                        conflicts.append(Conflict(
                            signal_id=signal_id,
                            agent_a=agent_a,
                            agent_b=agent_b,
                            type='confidence_conflict',
                            details={
                                'confidence_a': conf_a,
                                'confidence_b': conf_b,
                                'finding_a': finding_a,
                                'finding_b': finding_b
                            }
                        ))

        return conflicts

    @staticmethod
    def build_consensus(results: List[AgentResult]) -> ConsensusResult:
        if not results:
            return ConsensusResult(
                agreed_signals=[],
                disputed_signals=[],
                average_confidence=0.0,
                consensus_level='none'
            )

        signal_agents: Dict[str, List[tuple]] = {}
        signal_confidences: Dict[str, List[float]] = {}

        for result in results:
            for finding in result.findings:
                signal_id = finding.get('signal_id', '')
                if not signal_id:
                    continue
                if signal_id not in signal_agents:
                    signal_agents[signal_id] = []
                    signal_confidences[signal_id] = []
                signal_agents[signal_id].append((result.agent_name, finding))
                signal_confidences[signal_id].append(finding.get('confidence', 0))

        agreed_signals: List[str] = []
        disputed_signals: List[str] = []
        all_confidences: List[float] = []

        for signal_id, confidences in signal_confidences.items():
            all_confidences.extend(confidences)
            if len(signal_agents[signal_id]) > 1:
                if max(confidences) - min(confidences) <= 0.2:
                    agreed_signals.append(signal_id)
                else:
                    disputed_signals.append(signal_id)
            else:
                agreed_signals.append(signal_id)

        avg_confidence = sum(all_confidences) / len(all_confidences) if all_confidences else 0.0

        if not results:
            consensus_level = 'none'
        elif len(agreed_signals) == len(signal_agents):
            consensus_level = 'full'
        elif len(agreed_signals) > len(disputed_signals):
            consensus_level = 'partial'
        else:
            consensus_level = 'low'

        return ConsensusResult(
            agreed_signals=agreed_signals,
            disputed_signals=disputed_signals,
            average_confidence=avg_confidence,
            consensus_level=consensus_level
        )
