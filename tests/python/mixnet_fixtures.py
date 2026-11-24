"""Shared fixtures for the AFP mixnet test suite."""

import _path  # noqa: F401

import random

import afp_mixnet as mix
from afp_mixnet.directory import DirectoryBuilder, descriptor_for
from fixtures import make_witness


def build_mixnet(*, nodes_per_layer=2, layers_n=3, rng=None, quorum_threshold=2):
    """A verified 3-layer mixnet over distinct operators, with running mix nodes.

    Returns ``(mixnet, directory, builder, nodes)``. Every layer has
    ``nodes_per_layer`` nodes run by distinct operators (so §8.6 holds), and the
    directory is KERI-witness-signed and verified before the mixnet is built.
    """
    rng = rng or random.Random(1234)
    witnesses = [make_witness() for _ in range(3)]
    builder = DirectoryBuilder(witnesses, quorum_threshold=quorum_threshold)
    nodes = {}
    layers = []
    op_i = 0
    operators = [f"op-{i}" for i in range(100)]
    for layer_idx in range(layers_n):
        layer = []
        for j in range(nodes_per_layer):
            kp = mix.MixNodeKeypair.generate()
            aid = f"mix-L{layer_idx}-N{j}"
            op = operators[op_i]
            op_i += 1
            layer.append(
                descriptor_for(kp, mix_node_aid=aid, operator_aid=op, endpoint=f"{aid}.ex")
            )
            nodes[aid] = mix.MixNode(
                mix_node_aid=aid,
                operator_aid=op,
                layer_index=layer_idx,
                keypair=kp,
                rng=random.Random(op_i),  # deterministic delay sampling
            )
        layers.append(layer)

    directory = builder.build(
        epoch=1, layers=layers, keri_anchor_event_dig="Emixnet-anchor-001"
    )
    mix.verify_directory(
        directory, witness_keys=builder.witness_keys, quorum_threshold=quorum_threshold
    )
    mixnet = mix.Mixnet(directory, nodes, rng=rng)
    return mixnet, directory, builder, nodes
