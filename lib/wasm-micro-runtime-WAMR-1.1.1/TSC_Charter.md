# Project Technical Steering Committee (PTSC) Charter

## Section 1. Guiding Principle

The WebAssembly Micro Runtime (WAMR) project is part of the
Bytecode Alliance (BA) which operates transparently, openly,
collaboratively, and ethically. Project proposals, timelines, and status
must not merely be open, but also easily visible to outsiders.

## Section 2. Project Governance under Bytecode Alliance

Technical leadership for the WAMR projects within the Bytecode Alliance
is delegated to the projects through the project charter. Though the BA TSC
will not interfere with day-to-day discussions, votes or meetings of the PTSC,
the BA TSC may request additional amendments to the PTSC charter when
there is misalignment between the project charter and the BA mission and values.



The PTSC structure described in this document may be overhauled as part of
establishing a BA TSC in order to adhere to constraints or requirements that
TSC will impose on project-level governance.

## Section 3. Establishment of the PTSC

PTSC memberships are not time-limited. There is no maximum size of the PTSC.
The size is expected to vary in order to ensure adequate coverage of important
areas of expertise, balanced with the ability to make decisions efficiently.
The PTSC must have at least four members.

There is no specific set of requirements or qualifications for PTSC
membership beyond these rules. The PTSC may add additional members to the
PTSC by a standard PTSC motion and vote. A PTSC member may be removed from the
PTSC by voluntary resignation, by a standard PTSC motion, or in accordance to the
participation rules described below.

Changes to PTSC membership should be posted in the agenda, and may be suggested
as any other agenda item.

The PTSC may, at its discretion, invite any number of non-voting observers to
participate in the public portion of PTSC discussions and meetings.

The PTSC shall meet regularly using tools that enable participation by the
community (e.g. weekly on a Zulip channel, or through any other
appropriate means selected by the PTSC ). The meeting shall be directed by
the PTSC Chairperson. Responsibility for directing individual meetings may be
delegated by the PTSC Chairperson to any other PTSC member. Minutes or an
appropriate recording shall be taken and made available to the community
through accessible public postings.

PTSC members are expected to regularly participate in PTSC activities.

In the case where an individual PTSC member -- within any three month period --
attends fewer than 25% of the regularly scheduled meetings, does not
participate in PTSC discussions, *and* does not participate in PTSC votes, the
member shall be automatically removed from the PTSC. The member may be invited
to continue attending PTSC meetings as an observer.

## Section 4. Responsibilities of the PTSC

Subject to such policies as may be set by the BA TSC, the WAMR PTSC is
responsible for all technical development within the WAMR  project,
including:

* Setting release dates.
* Release quality standards.
* Technical direction.
* Project governance and process.
* GitHub repository hosting.
* Conduct guidelines.
* Maintaining the list of additional Collaborators.
* Development process and any coding standards.
* Mediating technical conflicts between Collaborators or Foundation
projects.

The PTSC will define WAMR project’s release vehicles.

## Section 5. WAMR Project Operations

The PTSC will establish and maintain a development process for the WAMR
project. The development process will establish guidelines
for how the developers and community will operate. It will, for example,
establish appropriate timelines for PTSC review (e.g. agenda items must be
published at least a certain number of hours in advance of a PTSC
meeting).

The PTSC and entire technical community will follow any processes as may
be specified by the Bytecode Alliance Board relating to the intake and license compliance
review of contributions, including the Bytecode Alliance IP Policy.

## Section 6. Elections

Leadership roles in the WAMR project will be peer elected
representatives of the community.

For election of persons (such as the PTSC Chairperson), a multiple-candidate
method should be used, such as:

* [Condorcet][] or
* [Single Transferable Vote][]

Multiple-candidate methods may be reduced to simple election by plurality
when there are only two candidates for one position to be filled. No
election is required if there is only one candidate and no objections to
the candidate's election. Elections shall be done within the projects by
the Collaborators active in the project.

The PTSC will elect from amongst voting PTSC members a PTSC Chairperson to
work on building an agenda for PTSC meetings. The PTSC shall hold annual

elections to select a PTSC Chairperson; there are no limits on the number
of terms a PTSC Chairperson may serve.

## Section 7. Voting

For internal project decisions, Collaborators shall operate under Lazy
Consensus. The PTSC shall establish appropriate guidelines for
implementing Lazy Consensus (e.g. expected notification and review time
periods) within the development process.

The PTSC follows a [Consensus Seeking][] decision making model. When an agenda
item has appeared to reach a consensus the moderator will ask "Does anyone
object?" as a final call for dissent from the consensus.

If an agenda item cannot reach a consensus a PTSC member can call for
either a closing vote or a vote to table the issue to the next meeting.
The call for a vote must be seconded by a majority of the PTSC or else the
discussion will continue.

For all votes, a simple majority of all PTSC members for, or against, the issue
wins. A PTSC member may choose to participate in any vote through abstention.

## Section 8. Project Roles

The WAMR git repository is maintained by the PTSC and
additional Collaborators who are added by the PTSC on an ongoing basis.

Individuals making significant and valuable contributions,
“Contributor(s)”, are made Collaborators and given commit-access to the
project. These individuals are identified by the PTSC and their addition
as Collaborators is discussed during a PTSC meeting. Modifications of the
contents of the git repository are made on a collaborative basis as defined in
the development process.

Collaborators may opt to elevate significant or controversial
modifications, or modifications that have not found consensus to the PTSC
for discussion by assigning the `tsc-agenda` tag to a pull request or
issue. The PTSC should serve as the final arbiter where required. The PTSC
will maintain and publish a list of current Collaborators, as
well as a development process guide for Collaborators and Contributors
looking to participate in the development effort.

## Section 9. Definitions

* **Contributors**: contribute code or other artifacts, but do not have
the right to commit to the code base. Contributors work with the
project’s Collaborators to have code committed to the code base. A
Contributor may be promoted to a Collaborator by the PTSC. Contributors should
rarely be encumbered by the PTSC.

* **Project**: a technical collaboration effort, e.g. a subsystem, that
is organized through the project creation process and approved by the
PTSC.

[Consensus Seeking]: https://en.wikipedia.org/wiki/Consensus-seeking_decision-making
[Condorcet]: https://en.wikipedia.org/wiki/Condorcet_method
[Single Transferable Vote]: https://en.wikipedia.org/wiki/Single_transferable_vote

