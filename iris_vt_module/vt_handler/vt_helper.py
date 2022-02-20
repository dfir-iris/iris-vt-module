import json
import traceback

from jinja2 import Template
import logging
from iris_interface import IrisInterfaceStatus

log = logging.getLogger('iris_vt_module.vt_helper')


def get_detected_urls_ratio(report):
    avg_urls_detect_ratio = None
    avg_urls_detect_ratio_str = "No information"
    nb_detected_urls = None
    if "detected_urls" in report:
        nb_detected_urls = len(report["detected_urls"])
        count_total = 0
        count_positives = 0

        for detected_url in report["detected_urls"]:
            count_total += detected_url.get('total')
            count_positives += detected_url.get('positives')

        if nb_detected_urls > 0:
            avg_urls_detect_ratio_str = f"{round(count_positives/nb_detected_urls, 2)} / " \
                                              f"{count_total/nb_detected_urls}"

            avg_urls_detect_ratio = round(count_positives/count_total, 2)*100

    return avg_urls_detect_ratio_str, avg_urls_detect_ratio, nb_detected_urls


def gen_domain_report_from_template(html_template, vt_report) -> IrisInterfaceStatus:
    """
    Generates an HTML report for domains, displayed as an attribute in the IOC

    :param html_template: A string representing the HTML template
    :param vt_report: The JSON report fetched with VT API
    :return: IrisInterfaceStatus
    """
    template = Template(html_template)
    context = vt_report
    results = context.get('results')

    context["avg_urls_detect_ratio"], _, context["nb_detected_urls"] = get_detected_urls_ratio(results)

    if "detected_downloaded_samples" in results:
        context["nb_detected_samples"] = len(results["detected_downloaded_samples"])
        count_total = 0
        count_positives = 0

        for samples in results["detected_downloaded_samples"]:
            count_total += samples.get('total')
            count_positives += samples.get('positives')

        if context['nb_detected_samples'] > 0:
            context["avg_samples_detect_ratio"] = f"{round(count_positives/context['nb_detected_samples'], 2)} / " \
                                                  f"{count_total/context['nb_detected_samples']}"
        else:
            context["avg_samples_detect_ratio"] = "No information"

    try:

        rendered = template.render(context)

    except Exception:
        log.error(traceback.format_exc())
        return IrisInterfaceStatus.I2Error(traceback.format_exc())

    return IrisInterfaceStatus.I2Success(data=rendered)


def gen_ip_report_from_template(html_template, vt_report) -> IrisInterfaceStatus:
    """
    Generates an HTML report for IP, displayed as an attribute in the IOC

    :param html_template: A string representing the HTML template
    :param vt_report: The JSON report fetched with VT API
    :return: IrisInterfaceStatus
    """
    template = Template(html_template)
    context = vt_report
    results = context.get('results')

    context["avg_urls_detect_ratio"], _, context["nb_detected_urls"] = get_detected_urls_ratio(results)

    if "detected_communicating_samples" in results:
        context["nb_detected_samples"] = len(results["detected_communicating_samples"])
        count_total = 0
        count_positives = 0

        for samples in results["detected_communicating_samples"]:
            count_total += samples.get('total')
            count_positives += samples.get('positives')

        if context['nb_detected_samples'] > 0:
            context["avg_samples_detect_ratio"] = f"{round(count_positives/context['nb_detected_samples'], 2)} / " \
                                                  f"{count_total/context['nb_detected_samples']}"
        else:
            context["avg_samples_detect_ratio"] = "No information"

    try:

        rendered = template.render(context)

    except Exception:
        print(traceback.format_exc())
        log.error(traceback.format_exc())
        return IrisInterfaceStatus.I2Error(traceback.format_exc())

    return IrisInterfaceStatus.I2Success(data=rendered)


def gen_hash_report_from_template(html_template, vt_report) -> IrisInterfaceStatus:
    """
    Generates an HTML report for hash, displayed as an attribute in the IOC

    :param html_template: A string representing the HTML template
    :param vt_report: The JSON report fetched with VT API
    :return: IrisInterfaceStatus
    """
    template = Template(html_template)
    context = vt_report

    try:

        rendered = template.render(context)

    except Exception:
        print(traceback.format_exc())
        log.error(traceback.format_exc())
        return IrisInterfaceStatus.I2Error(traceback.format_exc())

    return IrisInterfaceStatus.I2Success(data=rendered)