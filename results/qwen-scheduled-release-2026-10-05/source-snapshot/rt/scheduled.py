"""Defined fixed-slot interface; private workers and an independent publisher.

All public preflight is finished before the epoch is chosen; admission charges
are committed before any worker starts. No post-access state is published.
The slot-interface theorem assumes a trusted available publisher and transport;
OS publication jitter is measured separately, never hidden behind fake actual
timestamps. Linux isolation remains mandatory for all judge programs.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone
import multiprocessing
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
from . import bundle
from .bundle import sha
from .release import randomized_bucket
from .runner import version
from .sandbox import execute
from .schema import canonical
from .scheduled_log import policy,read,validate_entry


def sleep_until(target):
    while (remaining:=target-time.monotonic())>0:
        time.sleep(remaining)


def _publish(plans,readers,path,epoch_wall,epoch_mono,period,margin,meta,cpu,diagnostics):
    if cpu is not None:
        os.sched_setaffinity(0,{cpu})
    # Establish publisher readiness before choosing the epoch or allowing access.
    diagnostics.send({"ready":True})
    epoch=diagnostics.recv()
    epoch_wall,epoch_mono=epoch["wall"],epoch["monotonic"]
    path=Path(path)
    lock=path.with_name(path.name+".lock")
    fd=os.open(lock,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    prev=None
    actual=[]  # private research diagnostics, excluded from the public records
    received=[]
    try:
        with path.open("xb") as stream:
            for index,(plan,reader) in enumerate(zip(plans,readers)):
                due=epoch_mono+index*period
                sleep_until(due-margin)
                raw=(0,0)
                had_frame=False
                if plan["kind"]=="released":
                    try:
                        if reader.poll(0):
                            frame=reader.recv_bytes(2)
                            if len(frame)==2 and all(value<4 for value in frame):
                                raw=tuple(frame)
                                had_frame=True
                    except (EOFError,OSError):
                        pass
                # Always apply the same fresh trusted kernel, including every fallback.
                buckets=tuple(randomized_bucket(value,meta["flip_probability"]) for value in raw)
                received.append(had_frame)
                value={**plan,"schema":"rt.release.v2","seq":index,"prev":prev,"policy":meta,
                    "release_at":datetime.fromtimestamp(epoch_wall+index*period,timezone.utc).isoformat(timespec="microseconds")}
                if plan["kind"]=="released":
                    value["verdict"]={"schema":"rt.verdict.v1b","axes":dict(zip(("deception","sycophancy"),buckets)),"failure_tags":[]}
                value["entry_hash"]=sha(canonical(value))
                validate_entry(value)
                encoded=canonical(value)+b"\n"
                sleep_until(due)
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
                actual.append(time.monotonic()-due)
                prev=sha(encoded)
                reader.close()
        diagnostics.send({"publication_jitter_seconds":actual,"frame_received_before_cutoff":received})
    finally:
        os.close(fd)
        lock.unlink()
        for reader in readers:
            reader.close()
        diagnostics.close()


def run_batch(sources,models,budget,log_path,*,item_ids=None,item_budgets=None,p=0.5,period=0.25,
              window=1.0,margin=0.1,lead=2.0,max_workers=8,partition_cpus=True):
    if sys.platform!="linux":
        raise RuntimeError("Linux namespace sandbox required; use WSL.")
    if not sources or len(sources)>256 or len(sources)!=len(models) or not 0<margin<window or lead<window+margin:
        raise ValueError("invalid_fixed_batch")
    item_ids=item_ids or ["fixed-task" for _ in sources]
    if len(item_ids)!=len(sources) or (item_budgets is not None and len(item_budgets)!=len(sources)):
        raise ValueError("invalid_item_policy")
    meta=policy(p,period,window,margin,budget.scope,budget.cap)
    path=Path(log_path).resolve()
    path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists() or path.with_name(path.name+".lock").exists():
        raise ValueError("new_scheduled_log_required")
    rev=version()
    cpus=sorted(os.sched_getaffinity(0))
    if partition_cpus and len(cpus)<2:
        raise RuntimeError("Two CPUs required to separate the publisher; no weaker fallback.")
    pubcpu=cpus[0] if partition_cpus else None
    worker_cpus=set(cpus[1:]) if partition_cpus else None
    ctx=multiprocessing.get_context("spawn")
    plans,jobs,readers,writers=[],[],[],[]
    private=[{} for _ in sources]
    with tempfile.TemporaryDirectory(prefix="rt-fixed-batch-") as temp:
        temp=Path(temp)
        # Public verification and committed budget charges precede all private work.
        for index,(source,model,item_id) in enumerate(zip(sources,models,item_ids)):
            if type(item_id) is not str or not 1<=len(item_id)<=128:
                raise ValueError("invalid_public_item_id")
            base={"kind":"released","model_hash":model.model_hash,"bundle_hash":sha(b"unvalidated-bundle"),
                "method_card_hash":sha(b"unvalidated-method-card"),"runner_version":rev,
                "attestation":"software-sandbox-v2:"+rev,"slot":index,"item_id":item_id}
            snap,space=temp/str(index)/"bundle",temp/str(index)/"private"
            snap.mkdir(parents=True)
            space.mkdir(mode=0o700)
            manifest=None
            try:
                bundle.check(source)
                manifest=bundle.snapshot(source,snap)
                base.update(bundle_hash=manifest["bundle_id"],method_card_hash=manifest["method_card_hash"])
                if manifest["verdict_schema_id"]!="rt.verdict.v1b" or manifest["resources"]["max_seconds"]>window:
                    raise bundle.Rejected("resource_rejected")
                slot=budget.reserve_slot()
                if slot is None:
                    raise bundle.Rejected("release_budget_exhausted")
                if item_budgets is not None and not item_budgets[index].reserve():
                    raise bundle.Rejected("release_budget_exhausted")
                private[index]["charged"]=True
            except bundle.Rejected as exc:
                base.update(kind="refused",reason_code=exc.code)
            except (OSError,ValueError,TypeError):
                base.update(kind="refused",reason_code="schema_rejected")
            reader,writer=ctx.Pipe(duplex=False)
            plans.append(base)
            readers.append(reader)
            writers.append(writer)
            jobs.append((snap,space,manifest,model))
        # Wall-clock metadata and monotonic scheduling are fixed before access.
        diagnostics_reader,diagnostics_writer=ctx.Pipe(duplex=True)
        publisher=ctx.Process(target=_publish,args=(plans,readers,str(path),None,None,period,margin,
                                                    meta,pubcpu,diagnostics_writer))
        publisher.start()
        diagnostics_writer.close()
        if not diagnostics_reader.poll(10) or diagnostics_reader.recv()!={"ready":True}:
            publisher.terminate()
            publisher.join()
            raise RuntimeError("trusted_publisher_not_ready")
        epoch_mono=time.monotonic()+lead
        epoch_wall=time.time()+lead
        diagnostics_reader.send({"wall":epoch_wall,"monotonic":epoch_mono})
        for reader in readers:
            reader.close()
        def work(index):
            if worker_cpus is not None:
                os.sched_setaffinity(0,worker_cpus)  # Linux current thread; inherited by its judge children
            writer=writers[index]
            try:
                if plans[index]["kind"]!="released":
                    return
                sleep_until(epoch_mono+index*period-window)
                snap,space,manifest,model=jobs[index]
                result=execute(snap,space,manifest,model)
                private[index].update(error=result.error,actual_calls=result.n_calls)
                axes=result.verdict["axes"] if result.error is None else {"deception":0,"sycophancy":0}
                try:
                    writer.send_bytes(bytes(axes[name] for name in ("deception","sycophancy")))
                except (BrokenPipeError,EOFError,OSError):
                    pass  # publisher deliberately discards late proposals
            except BaseException:
                private[index]["error"]="private_worker_failure"
                try:
                    writer.send_bytes(b"\x00\x00")
                except (OSError,EOFError):
                    pass
            finally:
                writer.close()
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures=[pool.submit(work,index) for index in range(len(jobs))]
            # Independent publisher releases even if a worker has no result.
            publisher.join(timeout=lead+len(jobs)*period+window+5)
            if publisher.is_alive():
                publisher.terminate()
                publisher.join()
                raise RuntimeError("trusted_publisher_unavailable")
            if publisher.exitcode!=0:
                raise RuntimeError("trusted_publication_failed")
        stats=diagnostics_reader.recv()
        diagnostics_reader.close()
        # The trusted caller's completion gate is also fixed, not a worker join time.
        sleep_until(epoch_mono+(len(jobs)-1)*period+window+2)
    if version()!=rev:
        raise RuntimeError("source_changed_during_fixed_batch")
    entries=read(path)
    return entries,{**stats,"workers":private,"publisher_cpu":pubcpu,"worker_cpus":sorted(worker_cpus) if worker_cpus else cpus,
        "public_view":"scheduled records at fixed slots; private diagnostics excluded; physical OS/transport jitter outside the theorem"}


def main():
    import argparse
    from .budget import AdmissionBudget
    from .model import FixtureModel
    parser=argparse.ArgumentParser(description="Whole-record private release for the defined v1b fixed-slot task.")
    parser.add_argument("bundle")
    parser.add_argument("--log",required=True)
    parser.add_argument("--budget-ledger",required=True)
    parser.add_argument("--budget-scope",required=True)
    parser.add_argument("--release-cap",type=int,required=True)
    parser.add_argument("--noise-probability",type=float,default=0.5)
    args=parser.parse_args()
    budget=AdmissionBudget(args.budget_ledger,args.budget_scope,args.release_cap)
    entries,_=run_batch([args.bundle],[FixtureModel()],budget,args.log,p=args.noise_probability)
    print(entries[0]["kind"]+" "+entries[0]["entry_hash"])


if __name__=="__main__":
    main()
